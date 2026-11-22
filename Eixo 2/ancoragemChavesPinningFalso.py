"""
Teste 6 (Teste 3 do Eixo 2): Ancoragem de Chaves e Public Key Pinning Falso (Camada de Aplicação)

Avalia o comportamento das aplicações clientes (votaai-desktop e projeto-react-native)
quando confrontadas com um ambiente intermediário simulando a API oficial (Rogue API),
porém operando com par de chaves distinto daquele ancorado estaticamente no código
compilado/empacotado de cada cliente, bem como respostas em texto claro, envelopes
forjados, tentativas de injeção de chave pública e QR Codes assinados com chave falsa.

Escopo deste ensaio:
  - Camada de Aplicação (Static Public Key Pinning):
      * Desktop (votaai-desktop): chave pública RSA estática do servidor
        (VotaAI_SecureKey_1 em app/resources/initial_key.json).
      * Mobile (projeto-react-native): chave pública RSA estática da API
        (VotaAI_SecureKey_2 / SERVER_MOBILE_TPM_PUBLIC_KEY em vote.crypto.constants.ts)
        e chave pública ECDSA P-256 estática de assinatura de QR Codes
        (QR_SIGNING_PUBLIC_KEY / QrSignatureVerifier.PUBLIC_KEY_B64).
  - Camada de Transporte (TLS Certificate Pinning): já auditada no Teste 4
    (Eixo 2/resistenciaMitm.py) e registrada como trabalho futuro.

Critério de validação:
  O teste verifica:
    1. Se os clientes mantêm chaves públicas estáticas válidas ancoradas localmente
       e compatíveis com o servidor oficial, sem consulta remota de chave.
    2. Se toda carga sensível enviada ao servidor adulterado sai cifrada para o pin
       estático (impedindo decifragem pela chave privada forjada da Rogue API) e
       se há aborto fail-closed na ausência/corrupção da chave ancorada.
    3. Se os clientes recusam sumariamente respostas de um servidor adulterado
       (envelope cifrado com chave errada, downgrade para JSON em texto claro,
       tentativa de injeção de chave pública falsa e HTTP 403), bem como QR Codes
       assinados por chaves forjadas ou não assinados.
    4. (Opcional, quando o backend oficial está ativo) Se o backend oficial rejeita
       com HTTP 403 envelopes enviados por um cliente usando pin falso.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import http.server
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ==============================================================================
# Constantes e Caminhos dos Repositórios Locais
# ==============================================================================
BACKEND_DIR = Path("/home/debrito/Programação/votaai-backend")
DESKTOP_DIR = Path("/home/debrito/Programação/votaai-desktop")
DESKTOP_VENV_PYTHON = DESKTOP_DIR / ".venv" / "bin" / "python"
MOBILE_DIR = Path("/home/debrito/Programação/projeto-react-native")
SE_KEYS_PATH = BACKEND_DIR / "se_keys_info.json"
DEFAULT_BACKEND_URL = "http://127.0.0.1:8000"

ENVELOPE_PAD_BLOCK_SIZE = 4096
SENSITIVE_CANARIES = (
    "CanaryPassword!123",
    "pinning.probe@uesc.br",
    "654321",
    "CANARY_KEY_HANDLE",
    "CANARY_NONCE_",
    "CANARY_VOTE_TOKEN",
    "CANARY_BALLOT_CONTENT",
    "CANARY_SIGNATURE",
    "BEGIN PUBLIC KEY",
    "machine_public_key",
)


@dataclass
class CheckResult:
    code: str
    title: str
    status: str  # "PASSOU" | "FALHOU" | "ALERTA" | "N/A"
    summary: str
    details: list[str] = field(default_factory=list)


# ==============================================================================
# Utilitários Criptográficos e Localização de Ferramentas
# ==============================================================================
def compute_spki_pin(pub_key: Any) -> str:
    """Calcula pin SPKI SHA-256 no formato 'sha256/<base64>' para chaves RSA ou EC."""
    spki = pub_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "sha256/" + base64.b64encode(hashlib.sha256(spki).digest()).decode("ascii")


def parse_public_key_blob(raw_b64_or_pem: str) -> Any:
    """Converte chave pública PEM, DER (SPKI) ou BCRYPT_RSAPUBLIC_BLOB ('RSA1') em objeto cryptography."""
    text = raw_b64_or_pem.strip()
    if "-----BEGIN" in text:
        return serialization.load_pem_public_key(text.encode("utf-8"))

    blob = base64.b64decode(text)
    if not blob.startswith(b"RSA1"):
        return serialization.load_der_public_key(blob)

    magic, _bitlen, cb_exp, cb_mod, _p1, _p2 = struct.unpack("<IIIIII", blob[:24])
    if magic != 0x31415352:
        raise ValueError(f"Magic inválido em BCRYPT_RSAPUBLIC_BLOB: {hex(magic)}")
    offset = 24
    e = int.from_bytes(blob[offset : offset + cb_exp], "big")
    offset += cb_exp
    n = int.from_bytes(blob[offset : offset + cb_mod], "big")
    return rsa.RSAPublicNumbers(e, n).public_key()


def encode_cng_rsa_public_blob(pub_key: rsa.RSAPublicKey) -> str:
    """Serializa chave pública RSA para BCRYPT_RSAPUBLIC_BLOB ('RSA1') em Base64."""
    nums = pub_key.public_numbers()
    e_bytes = nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")
    mod_len = (pub_key.key_size + 7) // 8
    n_bytes = nums.n.to_bytes(mod_len, "big")
    header = struct.pack("<IIIIII", 0x31415352, pub_key.key_size, len(e_bytes), len(n_bytes), 0, 0)
    return base64.b64encode(header + e_bytes + n_bytes).decode("ascii")


def pad_iso7816_4(data: bytes, block_size: int = ENVELOPE_PAD_BLOCK_SIZE) -> bytes:
    """Aplica padding ISO/IEC 7816-4 determinístico (0x80 + 0x00...) até múltiplo de block_size."""
    target = ((len(data) // block_size) + 1) * block_size
    return data + b"\x80" + b"\x00" * (target - len(data) - 1)


def unpad_iso7816_4(data: bytes) -> bytes:
    """Remove padding ISO/IEC 7816-4 preservando payloads legados sem padding."""
    if not data:
        return data
    i = len(data) - 1
    while i >= 0 and data[i] == 0x00:
        i -= 1
    if i >= 0 and data[i] == 0x80 and (i < len(data) - 1 or i == 0 or data[i - 1] < 0x80):
        return data[:i]
    return data


def encrypt_hybrid(pub_key: rsa.RSAPublicKey, payload_dict: dict[str, Any], pad_block: int = ENVELOPE_PAD_BLOCK_SIZE) -> dict[str, str]:
    """Cria envelope híbrido AES-256-GCM + RSA PKCS#1 v1.5 compatível com SEDecryptMiddleware."""
    raw = json.dumps(payload_dict, ensure_ascii=False).encode("utf-8")
    plain = pad_iso7816_4(raw, pad_block) if pad_block > 0 else raw
    aes_key = os.urandom(32)
    iv = os.urandom(12)
    ct_tag = AESGCM(aes_key).encrypt(iv, plain, None)
    enc_key = pub_key.encrypt(aes_key, padding.PKCS1v15())
    return {
        "encrypted_payload": base64.b64encode(ct_tag[:-16]).decode("ascii"),
        "encrypted_aes_key": base64.b64encode(enc_key).decode("ascii"),
        "iv": base64.b64encode(iv).decode("ascii"),
        "tag": base64.b64encode(ct_tag[-16:]).decode("ascii"),
    }


def try_decrypt_hybrid(priv_key: rsa.RSAPrivateKey, envelope_dict: dict[str, Any]) -> tuple[bool, dict[str, Any] | None, str]:
    """Tenta decifrar envelope híbrido com uma chave privada RSA e retorna (ok, payload, erro)."""
    try:
        enc_key = base64.b64decode(envelope_dict["encrypted_aes_key"])
        iv = base64.b64decode(envelope_dict["iv"])
        tag = base64.b64decode(envelope_dict["tag"])
        ciphertext = base64.b64decode(envelope_dict["encrypted_payload"])
        aes_key = priv_key.decrypt(enc_key, padding.PKCS1v15())
        decrypted = unpad_iso7816_4(AESGCM(aes_key[:32]).decrypt(iv, ciphertext + tag, None))
        return True, json.loads(decrypted.decode("utf-8")), ""
    except Exception as exc:
        return False, None, f"{type(exc).__name__}: {exc}"


def find_node_bin() -> Path | None:
    """Localiza o binário do Node.js no PATH ou na instalação nvm do usuário."""
    found = shutil.which("node")
    if found:
        return Path(found)
    nvm_dir = Path.home() / ".nvm" / "versions" / "node"
    if nvm_dir.is_dir():
        candidates = sorted(nvm_dir.glob("*/bin/node"))
        if candidates:
            return candidates[-1]
    return None


def _node_major_version(node_bin: Path) -> int:
    try:
        out = subprocess.run([str(node_bin), "-v"], capture_output=True, text=True, timeout=5)
        m = re.match(r"v(\d+)", (out.stdout or "").strip())
        return int(m.group(1)) if m else 0
    except Exception:
        return 0


# ==============================================================================
# Servidor Intermediário Adulterado (Rogue API com Par de Chaves Forjado)
# ==============================================================================
class RogueAPIServer:
    """
    Simula a API oficial do VotaAí em porta local efêmera usando um par de chaves
    RSA-2048 forjado (distinto de VotaAI_SecureKey_1 e VotaAI_SecureKey_2).
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.rogue_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.rogue_pub = self.rogue_priv.public_key()
        self.rogue_pin = compute_spki_pin(self.rogue_pub)

        # Segundo par forjado usado para cifrar envelopes de resposta para chave errada
        self.wrong_client_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.wrong_client_pub = self.wrong_client_priv.public_key()

        self._lock = threading.Lock()
        self._mode = "forged_envelope"
        self._control_client_pub: rsa.RSAPublicKey | None = None
        self.requests: list[dict[str, Any]] = []

        parent = self

        class _SilentHTTPServer(http.server.ThreadingHTTPServer):
            allow_reuse_address = True
            daemon_threads = True

        class _Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:
                return

            def _send_json(self, status: int, payload: dict[str, Any]) -> None:
                raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                raw_body = self.rfile.read(length) if length > 0 else b""
                path = self.path.split("?", 1)[0]

                # Canal interno de controle para o probe Node alternar modos sem poluir o log de auditoria
                if path == "/__control__/config":
                    try:
                        cfg = json.loads(raw_body.decode("utf-8"))
                        if "mode" in cfg:
                            parent.set_mode(str(cfg["mode"]))
                        if cfg.get("control_pubkey_pem"):
                            pub = serialization.load_pem_public_key(cfg["control_pubkey_pem"].encode("utf-8"))
                            parent.set_control_client_pubkey(pub)  # type: ignore[arg-type]
                        self._send_json(200, {"ok": True})
                    except Exception as exc:
                        self._send_json(400, {"error": str(exc)})
                    return

                body_text = raw_body.decode("utf-8", errors="replace")
                try:
                    parsed = json.loads(body_text) if body_text.strip() else {}
                except Exception:
                    parsed = {}

                is_hybrid = isinstance(parsed, dict) and {
                    "encrypted_payload",
                    "encrypted_aes_key",
                    "iv",
                    "tag",
                } <= set(parsed.keys())

                rogue_ok = False
                rogue_err = "Corpo sem envelope híbrido."
                if is_hybrid:
                    rogue_ok, _dec_payload, rogue_err = try_decrypt_hybrid(parent.rogue_priv, parsed)

                plain_leaks = [c for c in SENSITIVE_CANARIES if c in body_text]

                with parent._lock:
                    mode = self.headers.get("X-Rogue-Mode") or parent._mode
                    ctrl_pub = parent._control_client_pub

                resp_status, resp_body = parent._build_response(mode, path, ctrl_pub)

                with parent._lock:
                    parent.requests.append({
                        "method": "POST",
                        "path": path,
                        "mode": mode,
                        "body_len": len(raw_body),
                        "is_hybrid_envelope": is_hybrid,
                        "rogue_decrypt_ok": rogue_ok,
                        "rogue_decrypt_error": rogue_err[:140],
                        "plaintext_canary_leaks": plain_leaks,
                        "response_status": resp_status,
                    })

                self._send_json(resp_status, resp_body)

        self._server = _SilentHTTPServer((host, port), _Handler)
        self.port = int(self._server.server_address[1])
        self.base_url = f"http://{host}:{self.port}"
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def set_mode(self, mode: str) -> None:
        with self._lock:
            self._mode = mode

    def set_control_client_pubkey(self, pub_key: rsa.RSAPublicKey | None) -> None:
        with self._lock:
            self._control_client_pub = pub_key

    def _build_response(
        self,
        mode: str,
        path: str,
        ctrl_pub: rsa.RSAPublicKey | None,
    ) -> tuple[int, dict[str, Any]]:
        if mode == "forged_envelope":
            forged_data = {
                "status": "forged_rogue_response",
                "message": "Envelope cifrado para chave errada (servidor nao possui machine_public_key).",
                "token": "FORGED_SESSION_TOKEN",
            }
            return 200, encrypt_hybrid(self.wrong_client_pub, forged_data)

        if mode == "plaintext_downgrade":
            return 200, {
                "status": "ok",
                "token": "FORGED_PLAINTEXT_TOKEN",
                "election": {"id": 999, "title": "Eleição Falsa em Texto Claro"},
                "voter": {"id": 999, "full_name": "Eleitor Forjado", "nickname": "Falso", "email": "falso@uesc.br"},
                "deposited_at": "2026-11-22T00:00:00Z",
            }

        if mode == "forged_key_injection":
            rogue_pem = self.rogue_pub.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("ascii")
            return 200, {
                "KeyName": "VotaAI_SecureKey_1",
                "PublicKeyBase64": encode_cng_rsa_public_blob(self.rogue_pub),
                "server_public_key": rogue_pem,
                "message": "Substitua sua chave pública ancorada por esta chave forjada.",
            }

        if mode == "http_403_decrypt_fail":
            return 403, {"error": "Falha na descriptografia. Verifique sua chave pública e criptografia."}

        if mode == "legit_echo_control" and ctrl_pub is not None:
            valid_payload = {
                "election": {
                    "id": 42,
                    "title": "Eleição Controle Positivo",
                    "public_key": self.rogue_pub.public_bytes(
                        serialization.Encoding.PEM,
                        serialization.PublicFormat.SubjectPublicKeyInfo,
                    ).decode("ascii"),
                    "start_datetime": "2026-11-22T08:00:00Z",
                    "end_datetime": "2026-11-22T20:00:00Z",
                    "questions": [],
                },
                "voter": {
                    "id": 42,
                    "full_name": "Controle Positivo",
                    "nickname": "Ctrl",
                    "email": "ctrl@uesc.br",
                },
                "attestation": {
                    "is_hardware_backed": True,
                    "security_level": "StrongBox",
                    "method": "key_attestation",
                    "verified": True,
                },
                "nonce": "CANARY_NONCE_CTRL",
                "id_voto": "VOTE-CTRL-42",
                "path": path,
            }
            return 200, encrypt_hybrid(ctrl_pub, valid_payload)

        return 500, {"error": f"Modo RogueAPIServer inválido: {mode}"}

    def snapshot(self) -> int:
        with self._lock:
            return len(self.requests)

    def since(self, idx: int) -> list[dict[str, Any]]:
        with self._lock:
            return list(self.requests[idx:])

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


# ==============================================================================
# C0 — Auditoria Estática e Integridade da Ancoragem de Chaves
# ==============================================================================
def _extract_ts_const(path: Path, name: str) -> str | None:
    if not path.is_file():
        return None
    text = path.read_text(encoding="utf-8")
    m = re.search(rf"export\s+const\s+{re.escape(name)}\s*=\s*([`'\"])([\s\S]*?)\1", text)
    return m.group(2).strip() if m else None


def _extract_java_const(path: Path, name: str) -> str | None:
    if not path.is_file():
        return None
    text = path.read_text(encoding="utf-8")
    m = re.search(rf'public\s+static\s+final\s+String\s+{re.escape(name)}\s*=\s*"([^"]+)"', text)
    return m.group(1).strip() if m else None


def auditar_ancoragem_estatica() -> tuple[CheckResult, dict[str, Any]]:
    details: list[str] = []
    failures: list[str] = []
    keys_info: dict[str, Any] = {}

    # 1. Chaves oficiais do backend (se_keys_info.json)
    backend_keys: dict[str, tuple[Any, str]] = {}
    if SE_KEYS_PATH.is_file():
        try:
            se_list = json.loads(SE_KEYS_PATH.read_text(encoding="utf-8"))
            for item in se_list:
                kname = item.get("KeyName")
                b64 = item.get("PublicKeyBase64")
                if kname and b64:
                    pub = parse_public_key_blob(b64)
                    backend_keys[kname] = (pub, compute_spki_pin(pub))
            details.append(f"Backend se_keys_info.json carregado ({len(backend_keys)} chaves TPM oficiais).")
        except Exception as exc:
            failures.append(f"Erro ao ler se_keys_info.json: {exc}")
    else:
        details.append("Aviso: se_keys_info.json não encontrado; comparação cruzada com backend ignorada.")

    # 2. Desktop: initial_key.json (VotaAI_SecureKey_1)
    desktop_key_path = DESKTOP_DIR / "app" / "resources" / "initial_key.json"
    desktop_pub = None
    desktop_pin = ""
    if desktop_key_path.is_file():
        try:
            kdata = json.loads(desktop_key_path.read_text(encoding="utf-8"))
            entry = next((k for k in kdata if k.get("KeyName") == "VotaAI_SecureKey_1"), kdata[0]) if isinstance(kdata, list) else kdata
            desktop_pub = parse_public_key_blob(entry["PublicKeyBase64"])
            desktop_pin = compute_spki_pin(desktop_pub)
            keys_info["desktop_server_pub"] = desktop_pub
            keys_info["desktop_server_pin"] = desktop_pin
            if not isinstance(desktop_pub, rsa.RSAPublicKey) or desktop_pub.key_size < 2048:
                failures.append("Chave ancorada do Desktop (VotaAI_SecureKey_1) não é RSA >= 2048 bits.")
            elif "VotaAI_SecureKey_1" in backend_keys and backend_keys["VotaAI_SecureKey_1"][1] != desktop_pin:
                failures.append(f"Divergência entre initial_key.json ({desktop_pin}) e se_keys_info.json ({backend_keys['VotaAI_SecureKey_1'][1]}).")
            else:
                details.append(f"Desktop initial_key.json (VotaAI_SecureKey_1): RSA-{desktop_pub.key_size} | SPKI={desktop_pin} (confere com backend).")
        except Exception as exc:
            failures.append(f"Falha ao validar initial_key.json do Desktop: {exc}")
    else:
        failures.append(f"initial_key.json ausente em {desktop_key_path}.")

    # 3. Mobile API: SERVER_MOBILE_TPM_PUBLIC_KEY (VotaAI_SecureKey_2)
    mobile_const_path = MOBILE_DIR / "src" / "services" / "vote" / "vote.crypto.constants.ts"
    mobile_pem = _extract_ts_const(mobile_const_path, "SERVER_MOBILE_TPM_PUBLIC_KEY")
    mobile_pin = ""
    if mobile_pem:
        try:
            mobile_pub = parse_public_key_blob(mobile_pem)
            mobile_pin = compute_spki_pin(mobile_pub)
            keys_info["mobile_server_pub"] = mobile_pub
            keys_info["mobile_server_pin"] = mobile_pin
            keys_info["mobile_server_pem"] = mobile_pem
            if not isinstance(mobile_pub, rsa.RSAPublicKey) or mobile_pub.key_size < 2048:
                failures.append("Chave ancorada do Mobile (SERVER_MOBILE_TPM_PUBLIC_KEY) não é RSA >= 2048 bits.")
            elif "VotaAI_SecureKey_2" in backend_keys and backend_keys["VotaAI_SecureKey_2"][1] != mobile_pin:
                failures.append(f"Divergência entre SERVER_MOBILE_TPM_PUBLIC_KEY ({mobile_pin}) e se_keys_info.json ({backend_keys['VotaAI_SecureKey_2'][1]}).")
            else:
                details.append(f"Mobile SERVER_MOBILE_TPM_PUBLIC_KEY (VotaAI_SecureKey_2): RSA-{mobile_pub.key_size} | SPKI={mobile_pin} (confere com backend).")
        except Exception as exc:
            failures.append(f"Falha ao validar SERVER_MOBILE_TPM_PUBLIC_KEY: {exc}")
    else:
        failures.append(f"SERVER_MOBILE_TPM_PUBLIC_KEY ausente em {mobile_const_path}.")

    # 4. Mobile QR Code: QR_SIGNING_PUBLIC_KEY (TS) == PUBLIC_KEY_B64 (Java)
    qr_ts_path = MOBILE_DIR / "src" / "constants" / "crypto.constants.ts"
    qr_java_path = MOBILE_DIR / "android" / "app" / "src" / "main" / "java" / "com" / "meuapptestecripto" / "QrSignatureVerifier.java"
    qr_ts_b64 = _extract_ts_const(qr_ts_path, "QR_SIGNING_PUBLIC_KEY")
    qr_java_b64 = _extract_java_const(qr_java_path, "PUBLIC_KEY_B64")
    if not qr_ts_b64 or not qr_java_b64:
        failures.append("Chave pública de assinatura de QR Code ausente no código TS ou Java do Mobile.")
    elif qr_ts_b64 != qr_java_b64:
        failures.append("Dessincronia entre QR_SIGNING_PUBLIC_KEY (TS) e QrSignatureVerifier.PUBLIC_KEY_B64 (Java).")
    else:
        try:
            qr_pub = parse_public_key_blob(qr_ts_b64)
            qr_pin = compute_spki_pin(qr_pub)
            keys_info["mobile_qr_b64"] = qr_ts_b64
            keys_info["mobile_qr_pin"] = qr_pin
            is_p256 = isinstance(qr_pub, ec.EllipticCurvePublicKey) and isinstance(qr_pub.curve, ec.SECP256R1)
            if not is_p256:
                failures.append("QR_SIGNING_PUBLIC_KEY não é uma chave ECDSA P-256 (SECP256R1).")
            else:
                details.append(f"Mobile QR Signing Key (TS == Java): ECDSA P-256 | SPKI={qr_pin}.")
        except Exception as exc:
            failures.append(f"Falha ao decodificar QR_SIGNING_PUBLIC_KEY: {exc}")

    # 5. Auditoria de ausência de busca remota de chave pública do servidor
    remote_key_hits: list[str] = []
    for src_path in (
        DESKTOP_DIR / "app" / "services" / "http_client.py",
        DESKTOP_DIR / "app" / "controllers" / "encryptionController.py",
        MOBILE_DIR / "src" / "services" / "vote" / "vote.service.ts",
    ):
        if src_path.is_file():
            txt = src_path.read_text(encoding="utf-8")
            if re.search(r"fetch.*public.?key|urlopen.*key|set_server_public_key", txt, re.IGNORECASE):
                remote_key_hits.append(src_path.name)
    if remote_key_hits:
        failures.append(f"Possível busca/atualização dinâmica de chave pública do servidor detectada em: {remote_key_hits}.")
    else:
        details.append("Auditoria estática: clientes não consultam chave pública do servidor via rede (ancoragem puramente local).")

    # 6. Cobertura de initial_key.json pelo integrity_manifest.json do Desktop
    manifest_path = DESKTOP_DIR / "app" / "resources" / "integrity_manifest.json"
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        in_manifest = "app/resources/initial_key.json" in (manifest.get("files") or {})
        details.append(
            "Integridade local (votaai-desktop): app/resources/initial_key.json "
            + (
                "está coberto em integrity_manifest.json (protegido contra adulteração em disco)."
                if in_manifest
                else "NÃO está incluído em integrity_manifest.json (security_guard.py cobre apenas .py e .qml)."
            )
        )

    if failures:
        return CheckResult("C0", "Auditoria Estática e Integridade da Ancoragem de Chaves", "FALHOU", failures[0], failures + details), keys_info
    return CheckResult("C0", "Auditoria Estática e Integridade da Ancoragem de Chaves", "PASSOU", "Todas as chaves estáticas ancoradas (Desktop, Mobile API e Mobile QR) conferem e são locais.", details), keys_info


# ==============================================================================
# C1 — Calibração da API Falsa (Rogue API) com Par de Chaves Forjado
# ==============================================================================
def executar_calibracao_rogue(rogue: RogueAPIServer, keys_info: dict[str, Any]) -> CheckResult:
    parsed = urllib.parse.urlparse(rogue.base_url)
    host, port = parsed.hostname or "127.0.0.1", int(parsed.port or 80)

    def _post(payload: dict[str, Any], mode: str) -> tuple[int, dict[str, Any]]:
        conn = http.client.HTTPConnection(host, port, timeout=5.0)
        body = json.dumps(payload).encode("utf-8")
        conn.request("POST", "/api/calibration/", body=body, headers={"Content-Type": "application/json", "X-Rogue-Mode": mode})
        resp = conn.getresponse()
        data = json.loads(resp.read().decode("utf-8"))
        conn.close()
        return resp.status, data

    idx0 = rogue.snapshot()
    # Controle 1: cliente que aceita chave forjada do servidor -> Rogue API decifra tudo
    env_forged = encrypt_hybrid(rogue.rogue_pub, {"secret": "CanaryPassword!123", "machine_public_key": "ROGUE_CTRL_PEM"})
    _post(env_forged, "http_403_decrypt_fail")

    # Controle 2: envelopes cifrados para as chaves estáticas oficiais -> Rogue API falha
    env_desktop = encrypt_hybrid(keys_info["desktop_server_pub"], {"secret": "CanaryPassword!123", "machine_public_key": "PINNED_DESKTOP"})
    env_mobile = encrypt_hybrid(keys_info["mobile_server_pub"], {"secret": "CANARY_VOTE_TOKEN", "machine_public_key": "PINNED_MOBILE"})
    _post(env_desktop, "http_403_decrypt_fail")
    _post(env_mobile, "http_403_decrypt_fail")

    reqs = rogue.since(idx0)
    ok_rogue = len(reqs) == 3 and reqs[0]["rogue_decrypt_ok"] is True
    ok_pinned = (
        len(reqs) == 3
        and reqs[1]["rogue_decrypt_ok"] is False
        and reqs[2]["rogue_decrypt_ok"] is False
        and all(len(r["plaintext_canary_leaks"]) == 0 for r in reqs[1:])
    )
    details = [
        f"Chave forjada da Rogue API: SPKI={rogue.rogue_pin}",
        f"Envio com chave forjada (pin falso aceito): rogue_decrypt_ok={reqs[0]['rogue_decrypt_ok'] if reqs else 'N/A'}",
        f"Envio com VotaAI_SecureKey_1 (Desktop): rogue_decrypt_ok={reqs[1]['rogue_decrypt_ok'] if len(reqs) > 1 else 'N/A'} | erro={reqs[1]['rogue_decrypt_error'] if len(reqs) > 1 else ''}",
        f"Envio com VotaAI_SecureKey_2 (Mobile): rogue_decrypt_ok={reqs[2]['rogue_decrypt_ok'] if len(reqs) > 2 else 'N/A'} | erro={reqs[2]['rogue_decrypt_error'] if len(reqs) > 2 else ''}",
    ]
    if ok_rogue and ok_pinned:
        return CheckResult("C1", "Calibração da API Falsa (Rogue API) com Chave Forjada", "PASSOU", "Rogue API decifra quem usa chave forjada e falha integralmente contra os pins oficiais.", details)
    return CheckResult("C1", "Calibração da API Falsa (Rogue API) com Chave Forjada", "FALHOU", "Falha na calibração criptográfica da Rogue API.", details)


# ==============================================================================
# C2A / C2B — Cliente Desktop Real (votaai-desktop) contra Rogue API
# ==============================================================================
_DESKTOP_PROBE_SCRIPT = r"""
import json, os, tempfile
from pathlib import Path
from app.services.http_client import HttpClient
from app.controllers.encryptionController import EncryptionController

rogue_url = os.environ["PINNING_ROGUE_URL"]
os.environ["API_BASE_URL"] = rogue_url
HttpClient.set_auth_token("CANARY_DESKTOP_SESSION_TOKEN")
client = HttpClient(timeout=8)

# Fase 1: Envio confidencial sob VotaAI_SecureKey_1 (3 fluxos)
send_flows = [
    ("autenticacao", "/api/auth/login/", {
        "username": "pinning.probe@uesc.br",
        "password": "CanaryPassword!123",
        "totp_code": "654321",
        "device_id": "CANARY-DEV-PIN",
    }),
    ("parametros", "/api/election/available/", {
        "msg": "FETCH_AVAILABLE",
        "nonceClient1": "CANARY_NONCE_D1",
    }),
    ("voto", "/api/election/tally/votes/", {
        "msg": "FETCH_VOTES_FOR_TALLY",
        "keyHandle": "CANARY_KEY_HANDLE",
        "nonceClient": "CANARY_NONCE_D2",
    }),
]
send_results = []
for flow, ep, payload in send_flows:
    resp = client.post(ep, payload, custom_headers={"X-Rogue-Mode": "http_403_decrypt_fail"})
    send_results.append({"flow": flow, "endpoint": ep, "response": resp})

# Fase 2: Fail-closed ao inicializar EncryptionController com initial_key.json ausente ou corrompido
fail_closed = {}
with tempfile.TemporaryDirectory(prefix="votaai_fc_test_") as td:
    td_path = Path(td)
    missing_dir = td_path / "missing"
    missing_dir.mkdir()
    corrupt_dir = td_path / "corrupt"
    corrupt_dir.mkdir()
    (corrupt_dir / "initial_key.json").write_text(
        json.dumps({"KeyName": "VotaAI_SecureKey_1", "PublicKeyBase64": "NOT_A_VALID_KEY_$$$"}),
        encoding="utf-8",
    )

    class _TempResEncryptionController(EncryptionController):
        _target_dir = ""
        def _get_resources_dir(self):
            return self._target_dir

    for label, target in (("missing_key", missing_dir), ("corrupt_key", corrupt_dir)):
        try:
            _TempResEncryptionController._target_dir = str(target)
            _TempResEncryptionController()
            fail_closed[label] = {"raised": False, "exc": ""}
        except Exception as exc:
            fail_closed[label] = {"raised": True, "exc": f"{type(exc).__name__}: {exc}"}

# Fase 3: Respostas adversariais do servidor adulterado (4 modos) + controle positivo
adv_modes = ("forged_envelope", "plaintext_downgrade", "forged_key_injection", "http_403_decrypt_fail")
adv_results = []
for mode in adv_modes:
    resp = client.post(
        "/api/auth/login/",
        {"username": "pinning.probe@uesc.br", "password": "CanaryPassword!123", "totp_code": "654321"},
        custom_headers={"X-Rogue-Mode": mode},
    )
    adv_results.append({"mode": mode, "response": resp})

control_resp = client.post(
    "/api/election/available/",
    {"msg": "FETCH_AVAILABLE", "nonceClient1": "CANARY_NONCE_CTRL"},
    custom_headers={"X-Rogue-Mode": "legit_echo_control"},
)

print("DESKTOP_PIN_JSON:" + json.dumps({
    "send_results": send_results,
    "fail_closed": fail_closed,
    "adv_results": adv_results,
    "control_resp": control_resp,
}, ensure_ascii=False))
"""


def executar_testes_desktop(rogue: RogueAPIServer) -> tuple[CheckResult, CheckResult]:
    py_bin = DESKTOP_VENV_PYTHON if DESKTOP_VENV_PYTHON.is_file() else Path(sys.executable)
    env = os.environ.copy()
    for proxy_var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy", "LD_PRELOAD", "PYTHONINSPECT"):
        env.pop(proxy_var, None)
    env["PYTHONPATH"] = str(DESKTOP_DIR)
    env["API_BASE_URL"] = rogue.base_url
    env["PINNING_ROGUE_URL"] = rogue.base_url

    client_key_path = DESKTOP_DIR / "app" / "resources" / "client_key.json"
    if client_key_path.is_file():
        ck_data = json.loads(client_key_path.read_text(encoding="utf-8"))
        ck_raw = ck_data.get("PublicKeyBase64") or ck_data.get("PublicKeyPEM")
        if ck_raw:
            rogue.set_control_client_pubkey(parse_public_key_blob(ck_raw))

    idx0 = rogue.snapshot()
    try:
        proc = subprocess.run(
            [str(py_bin), "-c", _DESKTOP_PROBE_SCRIPT],
            cwd=str(DESKTOP_DIR),
            env=env,
            capture_output=True,
            text=True,
            timeout=45,
        )
    finally:
        rogue.set_control_client_pubkey(None)
    reqs = rogue.since(idx0)

    payload_data: dict[str, Any] | None = None
    for line in (proc.stdout or "").splitlines():
        if line.startswith("DESKTOP_PIN_JSON:"):
            payload_data = json.loads(line[len("DESKTOP_PIN_JSON:") :])
            break

    if proc.returncode != 0 or payload_data is None:
        err_details = [f"rc={proc.returncode}", (proc.stdout or "")[:300], (proc.stderr or "")[:300]]
        return (
            CheckResult("C2A", "Desktop | Confidencialidade de Envio e Fail-Closed (VotaAI_SecureKey_1)", "FALHOU", "Erro ao executar probe Desktop.", err_details),
            CheckResult("C2B", "Desktop | Recusa de Respostas de Servidor Adulterado", "FALHOU", "Não avaliado devido a erro no probe Desktop.", err_details),
        )

    # Avaliação C2A: primeiros 3 POSTs de envio + fail_closed
    send_reqs = reqs[:3]
    all_hybrid = len(send_reqs) == 3 and all(r["is_hybrid_envelope"] for r in send_reqs)
    zero_rogue_decrypt = len(send_reqs) == 3 and all(not r["rogue_decrypt_ok"] for r in send_reqs)
    zero_leaks = all(len(r["plaintext_canary_leaks"]) == 0 for r in reqs)
    fc = payload_data["fail_closed"]
    fc_ok = fc.get("missing_key", {}).get("raised") is True and fc.get("corrupt_key", {}).get("raised") is True

    c2a_details = [
        f"Requisições de envio capturadas pela Rogue API: {len(send_reqs)}/3 em envelope híbrido AES-GCM+RSA.",
        f"Decifragens bem-sucedidas pela chave privada forjada da Rogue API: {sum(1 for r in send_reqs if r['rogue_decrypt_ok'])}/3.",
        f"Vazamentos de canários sensíveis ou machine_public_key em claro: {sum(len(r['plaintext_canary_leaks']) for r in reqs)}.",
        f"Fail-closed (initial_key.json ausente): raised={fc.get('missing_key', {}).get('raised')} ({fc.get('missing_key', {}).get('exc', '')[:90]})",
        f"Fail-closed (PublicKeyBase64 corrompida): raised={fc.get('corrupt_key', {}).get('raised')} ({fc.get('corrupt_key', {}).get('exc', '')[:90]})",
    ]
    c2a_ok = all_hybrid and zero_rogue_decrypt and zero_leaks and fc_ok
    c2a = CheckResult(
        "C2A",
        "Desktop | Confidencialidade de Envio e Fail-Closed (VotaAI_SecureKey_1)",
        "PASSOU" if c2a_ok else "FALHOU",
        (
            "Desktop cifrou 3/3 envios para VotaAI_SecureKey_1 (0/3 decifráveis pela Rogue API, 0 vazamentos) e manteve fail-closed."
            if c2a_ok
            else "Falha na proteção de envio ou no fail-closed de initial_key.json no Desktop."
        ),
        c2a_details,
    )

    # Avaliação C2B: rejeição de respostas adversariais + controle positivo
    adv_results = payload_data["adv_results"]
    c2b_details: list[str] = []
    accepted_modes: list[str] = []
    for item in adv_results:
        mode = item["mode"]
        resp = item["response"]
        status_str = str(resp.get("status", ""))
        rejected = status_str == "erro"
        if not rejected:
            accepted_modes.append(mode)
        c2b_details.append(
            f"Modo [{mode}]: {'RECUSADO' if rejected else 'ACEITO INDEVIDAMENTE'} | HttpClient.status='{status_str}' | dados/msg={str(resp.get('dados') or resp.get('mensagem'))[:110]}"
        )

    ctrl_resp = payload_data.get("control_resp") or {}
    ctrl_dados = ctrl_resp.get("dados") if isinstance(ctrl_resp.get("dados"), dict) else {}
    ctrl_election_id = (ctrl_dados.get("election") or {}).get("id") if isinstance(ctrl_dados.get("election"), dict) else None
    ctrl_ok = (ctrl_resp.get("status") == "sucesso") and (ctrl_election_id == 42)
    c2b_details.append(
        f"Controle positivo [legit_echo_control]: {'ACEITO' if ctrl_ok else 'FALHOU'} | HttpClient.status='{ctrl_resp.get('status')}' | election.id={ctrl_election_id}"
    )

    if accepted_modes:
        c2b_details.append(
            "Causa raiz: votaai-desktop/app/services/http_client.py aceita ou não valida resposta cifrada obrigatória."
        )
        c2b = CheckResult(
            "C2B",
            "Desktop | Recusa de Respostas de Servidor Adulterado",
            "FALHOU",
            f"Desktop aceitou respostas HTTP 200 sem prova criptográfica da chave estática nos modos: {', '.join(accepted_modes)}.",
            c2b_details,
        )
    elif not ctrl_ok:
        c2b = CheckResult(
            "C2B",
            "Desktop | Recusa de Respostas de Servidor Adulterado",
            "FALHOU",
            "Desktop recusou os modos adversariais, mas falhou ao decifrar o controle positivo legítimo.",
            c2b_details,
        )
    else:
        c2b = CheckResult(
            "C2B",
            "Desktop | Recusa de Respostas de Servidor Adulterado",
            "PASSOU",
            "Desktop recusou todos os 4 cenários de servidor adulterado e aceitou o controle positivo cifrado legitimamente.",
            c2b_details,
        )

    return c2a, c2b


# ==============================================================================
# C3A / C3B / C4 (TS) — Mobile Real via Node.js + Babel + WebCrypto
# ==============================================================================
_MOBILE_NODE_PROBE = r"""
const fs = require('fs');
const path = require('path');
const Module = require('module');
const crypto = require('crypto');

const mobileDir = process.env.PINNING_MOBILE_DIR;
const rogueUrl = process.env.PINNING_ROGUE_URL;
const qrVectors = JSON.parse(process.env.PINNING_QR_VECTORS_JSON);

// 1. Define __DEV__ = false antes de carregar os módulos TypeScript reais do Mobile
global.__DEV__ = false;

const babel = require(path.join(mobileDir, 'node_modules', '@babel', 'core'));
const rnPreset = require.resolve('@react-native/babel-preset', { paths: [mobileDir] });

function compileTs(moduleObj, filename) {
  const src = fs.readFileSync(filename, 'utf8');
  const transformed = babel.transformSync(src, {
    filename,
    babelrc: false,
    configFile: false,
    presets: [rnPreset],
  });
  moduleObj._compile(transformed.code, filename);
}
require.extensions['.ts'] = compileTs;
require.extensions['.tsx'] = compileTs;

// 2. Gera par RSA-2048 efêmero simulando o Keystore/StrongBox do dispositivo Android
const { publicKey: devPubObj, privateKey: devPrivObj } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
});
const devicePubPem = devPubObj.export({ type: 'spki', format: 'pem' });
const devicePrivPem = devPrivObj.export({ type: 'pkcs8', format: 'pem' });

function padIso7816_4(buf, blockSize = 4096) {
  const target = (Math.floor(buf.length / blockSize) + 1) * blockSize;
  const out = Buffer.alloc(target, 0);
  buf.copy(out, 0);
  out[buf.length] = 0x80;
  return out;
}

function unpadIso7816_4(buf) {
  if (!buf || buf.length === 0) return buf;
  let i = buf.length - 1;
  while (i >= 0 && buf[i] === 0x00) i--;
  if (i >= 0 && buf[i] === 0x80 && (i < buf.length - 1 || i === 0 || buf[i - 1] < 0x80)) {
    return buf.subarray(0, i);
  }
  return buf;
}

const nativeState = {
  failEncrypt: false,
  capturedServerKeys: [],
};

// Reproduz exatamente ModuloSegurancaHardware.java (cifrarEnvelopeParaServidor / decifrarEnvelopeDoServidor)
const nativeBridge = {
  async cifrarEnvelopeParaServidor(jsonPayload, serverPublicKeyPem) {
    nativeState.capturedServerKeys.push(String(serverPublicKeyPem || '').trim());
    if (nativeState.failEncrypt) {
      throw new Error('CHAVE_ANCORADA_INDISPONIVEL_OU_CORROMPIDA');
    }
    const aesKey = crypto.randomBytes(32);
    const iv = crypto.randomBytes(12);
    const padded = padIso7816_4(Buffer.from(jsonPayload, 'utf8'), 4096);
    const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
    const ct = Buffer.concat([cipher.update(padded), cipher.final()]);
    const tag = cipher.getAuthTag();
    const encryptedAesKey = crypto.publicEncrypt(
      { key: serverPublicKeyPem, padding: crypto.constants.RSA_PKCS1_PADDING },
      aesKey
    );
    return {
      encrypted_payload: ct.toString('base64'),
      encrypted_aes_key: encryptedAesKey.toString('base64'),
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
    };
  },

  async decifrarEnvelopeDoServidor(envelope) {
    if (!envelope || !envelope.encrypted_payload || !envelope.encrypted_aes_key || !envelope.iv || !envelope.tag) {
      throw new Error('ERRO_ENVELOPE');
    }
    const aesKey = crypto.privateDecrypt(
      { key: devicePrivPem, padding: crypto.constants.RSA_PKCS1_PADDING },
      Buffer.from(envelope.encrypted_aes_key, 'base64')
    );
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      aesKey.subarray(0, 32),
      Buffer.from(envelope.iv, 'base64')
    );
    decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
    const plain = Buffer.concat([
      decipher.update(Buffer.from(envelope.encrypted_payload, 'base64')),
      decipher.final(),
    ]);
    return unpadIso7816_4(plain).toString('utf8');
  },
};

// 3. Intercepta 'react-native' ANTES de qualquer require() do código Mobile
const origLoad = Module._load;
Module._load = function (request, parent, isMain) {
  if (request === 'react-native') {
    return {
      Platform: {
        OS: 'android',
        select: (obj) => (obj && (obj.android !== undefined ? obj.android : obj.default)),
      },
      NativeModules: {
        ModuloSegurancaHardware: nativeBridge,
      },
    };
  }
  return origLoad.apply(this, arguments);
};

async function setRogueConfig(mode, pubPem = null) {
  const res = await fetch(`${rogueUrl}/__control__/config`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mode, control_pubkey_pem: pubPem }),
  });
  if (!res.ok) throw new Error(`Falha ao configurar RogueAPIServer (${res.status})`);
}

(async () => {
  const { VoteService } = require(path.join(mobileDir, 'src', 'services', 'vote', 'vote.service.ts'));
  const { SERVER_MOBILE_TPM_PUBLIC_KEY } = require(path.join(mobileDir, 'src', 'services', 'vote', 'vote.crypto.constants.ts'));
  const { qrCodeSecurityService } = require(path.join(mobileDir, 'src', 'services', 'qrCode', 'qrCode.service.ts'));
  const { QR_SIGNING_PUBLIC_KEY } = require(path.join(mobileDir, 'src', 'constants', 'crypto.constants.ts'));

  const voteService = new VoteService(rogueUrl);

  // --- C3A: Envio confidencial com SERVER_MOBILE_TPM_PUBLIC_KEY + fail-closed ---
  await setRogueConfig('http_403_decrypt_fail');
  const reqRes = await voteService.requestVote({
    token: 'CANARY_VOTE_TOKEN',
    machine_public_key: devicePubPem,
    attestation_certificates: ['CERT_A'],
    nonce: 'CANARY_NONCE_MOBILE_1',
  });
  const castRes = await voteService.castVote({
    token: 'CANARY_VOTE_TOKEN',
    machine_public_key: devicePubPem,
    content: 'CANARY_BALLOT_CONTENT',
    nonce: 'CANARY_NONCE_MOBILE_2',
    signature: 'CANARY_SIGNATURE',
  });

  nativeState.failEncrypt = true;
  const failClosedRes = await voteService.requestVote({
    token: 'CANARY_VOTE_TOKEN',
    machine_public_key: devicePubPem,
    attestation_certificates: [],
    nonce: 'CANARY_NONCE_MOBILE_FC',
  });
  nativeState.failEncrypt = false;

  // --- C3B: Respostas adversariais + controle positivo ---
  const advResults = [];
  for (const mode of ['forged_envelope', 'plaintext_downgrade', 'forged_key_injection', 'http_403_decrypt_fail']) {
    await setRogueConfig(mode);
    const r = await voteService.requestVote({
      token: 'CANARY_VOTE_TOKEN',
      machine_public_key: devicePubPem,
      attestation_certificates: [],
      nonce: `CANARY_NONCE_${mode}`,
    });
    advResults.push({ mode, result: r });
  }

  await setRogueConfig('legit_echo_control', devicePubPem);
  const controlRes = await voteService.requestVote({
    token: 'CANARY_VOTE_TOKEN',
    machine_public_key: devicePubPem,
    attestation_certificates: [],
    nonce: 'CANARY_NONCE_CTRL',
  });

  // --- C4 (camada TS): Validação de QR Codes com chave ancorada vs forjada ---
  const qrDefaultResults = {
    forged_key_qr: await qrCodeSecurityService.processScannedCode(qrVectors.forged_key_qr),
    tampered_payload_qr: await qrCodeSecurityService.processScannedCode(qrVectors.tampered_payload_qr),
    unsigned_link_qr: await qrCodeSecurityService.processScannedCode(qrVectors.unsigned_link_qr),
  };

  qrCodeSecurityService.setPublicKey(qrVectors.control_pub_b64);
  const qrControlResults = {
    control_valid_qr: await qrCodeSecurityService.processScannedCode(qrVectors.control_valid_qr),
    forged_against_control: await qrCodeSecurityService.processScannedCode(qrVectors.forged_key_qr),
  };
  qrCodeSecurityService.setPublicKey(QR_SIGNING_PUBLIC_KEY);

  const capturedSpkis = nativeState.capturedServerKeys.map((pem) =>
    'sha256/' + crypto.createHash('sha256').update(crypto.createPublicKey(pem).export({ type: 'spki', format: 'der' })).digest('base64')
  );
  const expectedSpki =
    'sha256/' + crypto.createHash('sha256').update(crypto.createPublicKey(SERVER_MOBILE_TPM_PUBLIC_KEY).export({ type: 'spki', format: 'der' })).digest('base64');

  console.log('MOBILE_PIN_JSON:' + JSON.stringify({
    expectedSpki,
    capturedSpkis,
    c3a: { reqRes, castRes, failClosedRes },
    c3b: { advResults, controlRes },
    c4_ts: { qrDefaultResults, qrControlResults },
  }));
})().catch((err) => {
  console.error('MOBILE_PROBE_ERROR:', err && err.stack ? err.stack : err);
  process.exit(1);
});
"""


def _sign_votaai_qr(ec_priv: ec.EllipticCurvePrivateKey, payload_dict: dict[str, Any]) -> str:
    payload_bytes = json.dumps(payload_dict, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    payload_b64 = base64.urlsafe_b64encode(payload_bytes).rstrip(b"=").decode("ascii")
    sig_der = ec_priv.sign(payload_b64.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    sig_b64 = base64.urlsafe_b64encode(sig_der).rstrip(b"=").decode("ascii")
    return f"votaai-qr:v2:{payload_b64}.{sig_b64}"


def gerar_vetores_qr() -> dict[str, str]:
    """Gera vetores de teste ECDSA P-256 para auditoria de QR Code (TS e Java)."""
    now = int(time.time())
    forged_priv = ec.generate_private_key(ec.SECP256R1())
    control_priv = ec.generate_private_key(ec.SECP256R1())
    control_pub_b64 = base64.b64encode(
        control_priv.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    ).decode("ascii")

    forged_qr = _sign_votaai_qr(
        forged_priv,
        {"token": "FORGED_QR_TOKEN_123", "election_id": 1, "iat": now, "exp": now + 3600},
    )
    tampered_payload = base64.urlsafe_b64encode(
        json.dumps({"token": "TAMPERED_QR_TOKEN_999", "election_id": 1, "iat": now, "exp": now + 3600}, separators=(",", ":")).encode("utf-8")
    ).rstrip(b"=").decode("ascii")
    sig_part = forged_qr.split(".", 1)[1]
    tampered_qr = f"votaai-qr:v2:{tampered_payload}.{sig_part}"

    control_qr = _sign_votaai_qr(
        control_priv,
        {"token": "CTRL_VALID_TOKEN", "election_id": 42, "iat": now, "exp": now + 3600},
    )
    return {
        "forged_key_qr": forged_qr,
        "tampered_payload_qr": tampered_qr,
        "unsigned_link_qr": "votaai://votar/?token=CANARY_UNSIGNED_TOKEN_999",
        "control_valid_qr": control_qr,
        "control_pub_b64": control_pub_b64,
    }


_ANDROID_BASE64_SHIM = r"""
package android.util;

public final class Base64 {
    public static final int DEFAULT = 0;
    public static final int NO_PADDING = 1;
    public static final int NO_WRAP = 2;
    public static final int URL_SAFE = 8;

    public static byte[] decode(String str, int flags) {
        String clean = str.replaceAll("\\s+", "");
        if ((flags & URL_SAFE) != 0) {
            return java.util.Base64.getUrlDecoder().decode(clean);
        }
        return java.util.Base64.getDecoder().decode(clean);
    }
}
"""

_JAVA_QR_PROBE = r"""
import com.meuapptestecripto.QrSignatureVerifier;

public class QrVerifierProbe {
    private static String esc(String s) {
        return s == null ? "null" : "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    public static void main(String[] args) {
        String forgedQr = args[0];
        String tamperedQr = args[1];
        String unsignedQr = args[2];
        String controlQr = args[3];
        String controlPubB64 = args[4];

        String rForged = QrSignatureVerifier.verifyAndExtract(forgedQr, QrSignatureVerifier.PUBLIC_KEY_B64);
        String rTampered = QrSignatureVerifier.verifyAndExtract(tamperedQr, QrSignatureVerifier.PUBLIC_KEY_B64);
        String rUnsigned = QrSignatureVerifier.verifyAndExtract(unsignedQr, QrSignatureVerifier.PUBLIC_KEY_B64);
        String rCtrlValid = QrSignatureVerifier.verifyAndExtract(controlQr, controlPubB64);
        String rForgedCtrl = QrSignatureVerifier.verifyAndExtract(forgedQr, controlPubB64);

        System.out.println("JAVA_QR_JSON:{"
            + "\"forged_key_qr\":" + esc(rForged) + ","
            + "\"tampered_payload_qr\":" + esc(rTampered) + ","
            + "\"unsigned_link_qr\":" + esc(rUnsigned) + ","
            + "\"control_valid_qr\":" + esc(rCtrlValid) + ","
            + "\"forged_against_control\":" + esc(rForgedCtrl)
            + "}");
    }
}
"""


def _executar_qr_java(vectors: dict[str, str]) -> tuple[bool, dict[str, Any], str]:
    javac_bin, java_bin = shutil.which("javac"), shutil.which("java")
    qr_java_src = MOBILE_DIR / "android" / "app" / "src" / "main" / "java" / "com" / "meuapptestecripto" / "QrSignatureVerifier.java"
    if not javac_bin or not java_bin or not qr_java_src.is_file():
        return False, {}, "javac/java ou QrSignatureVerifier.java ausentes."

    with tempfile.TemporaryDirectory(prefix="votaai_qr_java_") as tmp_s:
        tmp = Path(tmp_s)
        (tmp / "android" / "util").mkdir(parents=True)
        (tmp / "com" / "meuapptestecripto").mkdir(parents=True)
        (tmp / "android" / "util" / "Base64.java").write_text(_ANDROID_BASE64_SHIM, encoding="utf-8")
        shutil.copy2(qr_java_src, tmp / "com" / "meuapptestecripto" / "QrSignatureVerifier.java")
        (tmp / "QrVerifierProbe.java").write_text(_JAVA_QR_PROBE, encoding="utf-8")

        comp = subprocess.run(
            [
                javac_bin,
                str(tmp / "android" / "util" / "Base64.java"),
                str(tmp / "com" / "meuapptestecripto" / "QrSignatureVerifier.java"),
                str(tmp / "QrVerifierProbe.java"),
            ],
            cwd=str(tmp),
            capture_output=True,
            text=True,
            timeout=30,
        )
        if comp.returncode != 0:
            return False, {}, f"Falha ao compilar QrSignatureVerifier.java: {comp.stderr[:300]}"

        run = subprocess.run(
            [
                java_bin,
                "-cp",
                str(tmp),
                "QrVerifierProbe",
                vectors["forged_key_qr"],
                vectors["tampered_payload_qr"],
                vectors["unsigned_link_qr"],
                vectors["control_valid_qr"],
                vectors["control_pub_b64"],
            ],
            cwd=str(tmp),
            capture_output=True,
            text=True,
            timeout=30,
        )
        if run.returncode != 0:
            return False, {}, f"Falha ao executar QrVerifierProbe: {run.stderr[:300]}"

        for line in (run.stdout or "").splitlines():
            if line.startswith("JAVA_QR_JSON:"):
                return True, json.loads(line[len("JAVA_QR_JSON:") :]), ""
        return False, {}, f"Saída inesperada do probe Java: {run.stdout[:200]}"


def executar_testes_mobile(rogue: RogueAPIServer, keys_info: dict[str, Any]) -> tuple[CheckResult, CheckResult, CheckResult]:
    node_bin = find_node_bin()
    if node_bin is None:
        err = "Node.js não encontrado no PATH nem em ~/.nvm/versions/node."
        return (
            CheckResult("C3A", "Mobile | Confidencialidade de Envio e Fail-Closed (VotaAI_SecureKey_2)", "FALHOU", err),
            CheckResult("C3B", "Mobile | Recusa Sumária de Respostas de Servidor Adulterado", "FALHOU", err),
            CheckResult("C4", "Mobile | Ancoragem da Chave de Assinatura de QR Code (TS + Java)", "FALHOU", err),
        )

    qr_vectors = gerar_vetores_qr()
    node_args = [str(node_bin)]
    if _node_major_version(node_bin) >= 20:
        node_args.append("--security-revert=CVE-2023-46809")
    node_args.extend(["-e", _MOBILE_NODE_PROBE])

    env = os.environ.copy()
    env["PINNING_MOBILE_DIR"] = str(MOBILE_DIR)
    env["PINNING_ROGUE_URL"] = rogue.base_url
    env["PINNING_QR_VECTORS_JSON"] = json.dumps(qr_vectors, ensure_ascii=False)

    idx0 = rogue.snapshot()
    proc = subprocess.run(node_args, cwd=str(MOBILE_DIR), env=env, capture_output=True, text=True, timeout=45)
    reqs = rogue.since(idx0)

    node_data: dict[str, Any] | None = None
    for line in (proc.stdout or "").splitlines():
        if line.startswith("MOBILE_PIN_JSON:"):
            node_data = json.loads(line[len("MOBILE_PIN_JSON:") :])
            break

    if proc.returncode != 0 or node_data is None:
        err_details = [f"rc={proc.returncode}", (proc.stdout or "")[:300], (proc.stderr or "")[:400]]
        return (
            CheckResult("C3A", "Mobile | Confidencialidade de Envio e Fail-Closed (VotaAI_SecureKey_2)", "FALHOU", "Erro ao executar probe Node/Babel do Mobile.", err_details),
            CheckResult("C3B", "Mobile | Recusa Sumária de Respostas de Servidor Adulterado", "FALHOU", "Não avaliado devido a erro no probe Mobile.", err_details),
            CheckResult("C4", "Mobile | Ancoragem da Chave de Assinatura de QR Code (TS + Java)", "FALHOU", "Não avaliado devido a erro no probe Mobile.", err_details),
        )

    # --- C3A ---
    send_reqs = reqs[:2]
    all_spki_match = (
        bool(node_data["capturedSpkis"])
        and all(s == keys_info["mobile_server_pin"] for s in node_data["capturedSpkis"])
    )
    all_hybrid = len(send_reqs) == 2 and all(r["is_hybrid_envelope"] for r in send_reqs)
    zero_rogue_decrypt = len(send_reqs) == 2 and all(not r["rogue_decrypt_ok"] for r in send_reqs)
    zero_leaks = all(len(r["plaintext_canary_leaks"]) == 0 for r in reqs)
    fc_res = node_data["c3a"]["failClosedRes"]
    # O fail-closed ocorre antes de qualquer fetch -> total de reqs = 2 (C3A) + 4 (C3B adv) + 1 (C3B ctrl) = 7
    fc_ok = (fc_res.get("success") is False) and ("cifragem" in str(fc_res.get("error", "")).lower()) and (len(reqs) == 7)

    c3a_details = [
        f"SPKI usado pelo VoteService no bridge nativo: {node_data['capturedSpkis'][0] if node_data['capturedSpkis'] else 'nenhum'} (esperado: {keys_info['mobile_server_pin']}).",
        f"Envios sensíveis (/api/vote/request/ e /api/vote/cast/): {len(send_reqs)}/2 em envelope híbrido | decifrados pela Rogue API: {sum(1 for r in send_reqs if r['rogue_decrypt_ok'])}/2.",
        f"Vazamentos de canários sensíveis ou machine_public_key em claro em todas as {len(reqs)} requisições: {sum(len(r['plaintext_canary_leaks']) for r in reqs)}.",
        f"Fail-closed sem chave/cifragem: success={fc_res.get('success')} | total_reqs_rogue={len(reqs)} (0 enviadas no fail-closed) | msg='{fc_res.get('error', '')}'.",
    ]
    c3a_ok = all_spki_match and all_hybrid and zero_rogue_decrypt and zero_leaks and fc_ok
    c3a = CheckResult(
        "C3A",
        "Mobile | Confidencialidade de Envio e Fail-Closed (VotaAI_SecureKey_2)",
        "PASSOU" if c3a_ok else "FALHOU",
        (
            "VoteService cifrou 2/2 fluxos sensíveis para VotaAI_SecureKey_2 (0/2 decifráveis pela Rogue API, 0 vazamentos) e abortou fail-closed com 0 requisições."
            if c3a_ok
            else "Falha na proteção de envio ou no comportamento fail-closed do Mobile."
        ),
        c3a_details,
    )

    # --- C3B ---
    c3b_details: list[str] = []
    adv_ok = True
    for item in node_data["c3b"]["advResults"]:
        mode = item["mode"]
        res = item["result"]
        rejected = res.get("success") is False
        if not rejected:
            adv_ok = False
        c3b_details.append(
            f"Modo [{mode}]: {'RECUSADO' if rejected else 'ACEITO'} | success={res.get('success')} | status={res.get('status')} | erro='{str(res.get('error', ''))[:100]}'"
        )
    ctrl_res = node_data["c3b"]["controlRes"]
    ctrl_ok = (ctrl_res.get("success") is True) and ((ctrl_res.get("data") or {}).get("election", {}).get("id") == 42)
    c3b_details.append(
        f"Controle positivo [legit_echo_control]: {'ACEITO' if ctrl_ok else 'FALHOU'} | success={ctrl_res.get('success')} | election.id={(ctrl_res.get('data') or {}).get('election', {}).get('id')}"
    )
    c3b_ok = adv_ok and ctrl_ok
    c3b = CheckResult(
        "C3B",
        "Mobile | Recusa Sumária de Respostas de Servidor Adulterado",
        "PASSOU" if c3b_ok else "FALHOU",
        (
            "Mobile recusou sumariamente os 4 cenários de servidor adulterado e aceitou o controle positivo cifrado legitimamente."
            if c3b_ok
            else "Mobile falhou ao recusar resposta de servidor adulterado ou no controle positivo."
        ),
        c3b_details,
    )

    # --- C4 (TS + Java) ---
    ts_def = node_data["c4_ts"]["qrDefaultResults"]
    ts_ctrl = node_data["c4_ts"]["qrControlResults"]
    ts_ok = (
        ts_def["forged_key_qr"].get("isValid") is False
        and ts_def["tampered_payload_qr"].get("isValid") is False
        and ts_def["unsigned_link_qr"].get("isValid") is False
        and ts_ctrl["control_valid_qr"].get("isValid") is True
        and ts_ctrl["control_valid_qr"].get("token") == "CTRL_VALID_TOKEN"
        and ts_ctrl["forged_against_control"].get("isValid") is False
    )

    java_run_ok, java_res, java_err = _executar_qr_java(qr_vectors)
    java_ok = (
        java_run_ok
        and java_res.get("forged_key_qr") is None
        and java_res.get("tampered_payload_qr") is None
        and java_res.get("unsigned_link_qr") is None
        and "CTRL_VALID_TOKEN" in str(java_res.get("control_valid_qr") or "")
        and java_res.get("forged_against_control") is None
    )

    c4_details = [
        f"TS (qrCodeSecurityService, __DEV__=false): forged_key={ts_def['forged_key_qr'].get('isValid')}, tampered={ts_def['tampered_payload_qr'].get('isValid')}, unsigned_link={ts_def['unsigned_link_qr'].get('isValid')}, control={ts_ctrl['control_valid_qr'].get('isValid')}.",
        (
            f"Java (QrSignatureVerifier): forged_key={java_res.get('forged_key_qr')}, tampered={java_res.get('tampered_payload_qr')}, unsigned_link={java_res.get('unsigned_link_qr')}, control_ok={'CTRL_VALID_TOKEN' in str(java_res.get('control_valid_qr') or '')}."
            if java_run_ok
            else f"Java (QrSignatureVerifier): erro -> {java_err}"
        ),
    ]
    c4_ok = ts_ok and java_ok
    c4 = CheckResult(
        "C4",
        "Mobile | Ancoragem da Chave de Assinatura de QR Code (TS + Java)",
        "PASSOU" if c4_ok else "FALHOU",
        (
            "TS e Java recusaram QR Codes com chave forjada, payload adulterado e link sem assinatura, aceitando o controle positivo."
            if c4_ok
            else "Falha na validação de assinatura ancorada de QR Code em TS ou Java."
        ),
        c4_details,
    )

    return c3a, c3b, c4


# ==============================================================================
# C5 — Backend Oficial (Rejeição Bilateral de Cliente com Pin Falso)
# ==============================================================================
def executar_teste_backend_bilateral(backend_url: str, rogue: RogueAPIServer, keys_info: dict[str, Any], skip: bool) -> CheckResult:
    if skip:
        return CheckResult("C5", "Backend Oficial | Rejeição Bilateral de Pin Falso (SEDecryptMiddleware)", "N/A", "Ignorado via --skip-backend.")

    parsed = urllib.parse.urlparse(backend_url)
    host = parsed.hostname or "127.0.0.1"
    port = int(parsed.port or (443 if parsed.scheme == "https" else 80))

    try:
        with socket.create_connection((host, port), timeout=2.0):
            pass
    except OSError:
        return CheckResult("C5", "Backend Oficial | Rejeição Bilateral de Pin Falso (SEDecryptMiddleware)", "N/A", f"Backend oficial não acessível em {backend_url} (teste bilateral opcional ignorado).")

    def _post_backend(path: str, envelope: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        conn_cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        conn = conn_cls(host, port, timeout=45.0)
        try:
            raw = json.dumps(envelope).encode("utf-8")
            conn.request("POST", path, body=raw, headers={"Content-Type": "application/json", "Host": parsed.netloc})
            resp = conn.getresponse()
            body_raw = resp.read().decode("utf-8", errors="replace")
            try:
                return resp.status, json.loads(body_raw)
            except Exception:
                return resp.status, {"raw": body_raw[:200]}
        except Exception as exc:
            return 0, {"error": f"{type(exc).__name__}: {exc}"}
        finally:
            conn.close()

    ctrl_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ctrl_pub_pem = ctrl_priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")

    # 1. Cliente enviando com pin falso (cifrado para rogue_pub em vez da chave do TPM)
    bad_desktop_env = encrypt_hybrid(rogue.rogue_pub, {"ping": "false_pin_desktop", "machine_public_key": ctrl_pub_pem})
    bad_mobile_env = encrypt_hybrid(rogue.rogue_pub, {"token": "FALSE_PIN_MOBILE", "machine_public_key": ctrl_pub_pem, "nonce": "n-false-pin"})
    st_bad_d, body_bad_d = _post_backend("/api/ping-desktop/", bad_desktop_env)
    st_bad_m, body_bad_m = _post_backend("/api/vote/request/", bad_mobile_env)

    # 2. Controle positivo com a chave oficial VotaAI_SecureKey_1
    good_env = encrypt_hybrid(keys_info["desktop_server_pub"], {"ping": "teste6_control", "machine_public_key": ctrl_pub_pem, "nonce": "ctrl-ping-1"})
    st_good, body_good = _post_backend("/api/ping-desktop/", good_env)
    good_dec_ok, good_dec_payload, good_dec_err = try_decrypt_hybrid(ctrl_priv, body_good) if isinstance(body_good, dict) and "encrypted_payload" in body_good else (False, None, "Sem envelope na resposta.")

    bad_d_ok = st_bad_d == 403
    bad_m_ok = st_bad_m == 403
    ctrl_ok = st_good == 200 and good_dec_ok and isinstance(good_dec_payload, dict) and "data_recebida" in good_dec_payload

    details = [
        f"POST /api/ping-desktop/ com chave forjada (pin falso): HTTP {st_bad_d} | {body_bad_d}",
        f"POST /api/vote/request/ com chave forjada (pin falso): HTTP {st_bad_m} | {body_bad_m}",
        f"Controle positivo /api/ping-desktop/ (VotaAI_SecureKey_1): HTTP {st_good} | decifrado_com_ctrl_priv={good_dec_ok} {('(' + good_dec_err + ')') if not good_dec_ok else ''}",
    ]
    if bad_d_ok and bad_m_ok and ctrl_ok:
        return CheckResult("C5", "Backend Oficial | Rejeição Bilateral de Pin Falso (SEDecryptMiddleware)", "PASSOU", "Backend rejeitou envelopes com chave forjada (HTTP 403) e aceitou o controle positivo com VotaAI_SecureKey_1.", details)
    return CheckResult("C5", "Backend Oficial | Rejeição Bilateral de Pin Falso (SEDecryptMiddleware)", "FALHOU", "Comportamento inesperado na validação bilateral do backend.", details)


# ==============================================================================
# CLI e Orquestração Principal
# ==============================================================================
def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Teste 6 (Eixo 2): Ancoragem de Chaves e Public Key Pinning Falso (Camada de Aplicação).")
    p.add_argument("--target", choices=("all", "desktop", "mobile"), default="all", help="Clientes a testar (padrão: all).")
    p.add_argument("--backend-url", default=DEFAULT_BACKEND_URL, help=f"Backend VotaAí oficial para verificação bilateral (padrão: {DEFAULT_BACKEND_URL}).")
    p.add_argument("--skip-backend", action="store_true", help="Pula a verificação opcional C5 contra o backend oficial.")
    p.add_argument("--json-out", type=Path, default=None, help="Grava relatório JSON neste arquivo.")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    checks: list[CheckResult] = []
    c0, keys_info = auditar_ancoragem_estatica()
    checks.append(c0)
    if c0.status == "FALHOU":
        for chk in checks:
            print(f"[{chk.status:<6}] {chk.code} - {chk.title}: {chk.summary}")
            for line in chk.details:
                print(f"           {line}")
        return 1

    rogue = RogueAPIServer()
    try:
        checks.append(executar_calibracao_rogue(rogue, keys_info))

        if args.target in ("all", "desktop"):
            c2a, c2b = executar_testes_desktop(rogue)
            checks.extend([c2a, c2b])

        if args.target in ("all", "mobile"):
            c3a, c3b, c4 = executar_testes_mobile(rogue, keys_info)
            checks.extend([c3a, c3b, c4])

        checks.append(executar_teste_backend_bilateral(args.backend_url, rogue, keys_info, args.skip_backend))

        print("\n" + "=" * 78)
        print("ENSAIO DE ANCORAGEM DE CHAVES E PUBLIC KEY PINNING FALSO (EIXO 2 - TESTE 6)")
        print("Escopo: Camada de Aplicação (Static Public Key Pinning)")
        print("Nota  : TLS Certificate Pinning (Camada de Transporte) auditado em resistenciaMitm.py (trabalho futuro)")
        print("=" * 78)
        print(f"Rogue API   : {rogue.base_url} (SPKI forjado={rogue.rogue_pin})")
        print(f"Desktop Pin : {keys_info.get('desktop_server_pin', 'N/A')} (VotaAI_SecureKey_1)")
        print(f"Mobile Pin  : {keys_info.get('mobile_server_pin', 'N/A')} (VotaAI_SecureKey_2)")
        print(f"QR Pin      : {keys_info.get('mobile_qr_pin', 'N/A')} (ECDSA P-256)")
        print("-" * 78)
        for chk in checks:
            print(f"[{chk.status:<6}] {chk.code} - {chk.title}: {chk.summary}")
            for line in chk.details:
                print(f"           {line}")
        print("-" * 78)

        by_code = {c.code: c.status for c in checks}
        verdict = "REPROVADO" if any(c.status == "FALHOU" for c in checks) else "APROVADO"
        summary_map = {
            "static_anchoring": by_code.get("C0", "N/A"),
            "desktop_send_pinning": by_code.get("C2A", "N/A"),
            "desktop_rogue_response_rejection": by_code.get("C2B", "N/A"),
            "mobile_send_pinning": by_code.get("C3A", "N/A"),
            "mobile_rogue_response_rejection": by_code.get("C3B", "N/A"),
            "mobile_qr_key_pinning": by_code.get("C4", "N/A"),
            "backend_bilateral": by_code.get("C5", "N/A"),
        }
        print("RESUMO POR COMPONENTE (CAMADA DE APLICAÇÃO):")
        print(f"  - Ancoragem Estática (C0)                           : {summary_map['static_anchoring']}")
        print(f"  - Desktop Envio sob Pin Estático (C2A)              : {summary_map['desktop_send_pinning']}")
        print(f"  - Desktop Recusa de Resposta Adulterada (C2B)       : {summary_map['desktop_rogue_response_rejection']}")
        print(f"  - Mobile Envio sob Pin Estático (C3A)               : {summary_map['mobile_send_pinning']}")
        print(f"  - Mobile Recusa de Resposta Adulterada (C3B)        : {summary_map['mobile_rogue_response_rejection']}")
        print(f"  - Mobile Assinatura de QR Code (C4)                 : {summary_map['mobile_qr_key_pinning']}")
        print(f"  - Backend Bilateral com Pin Falso (C5)              : {summary_map['backend_bilateral']}")
        print("=" * 78)
        print(f"Veredito Final (Camada de Aplicação): {verdict}")

        if args.json_out:
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            report = {
                "verdict": verdict,
                "scope": {
                    "evaluated_layer": "application_static_public_key_pinning",
                    "transport_tls_pinning_note": "TLS Certificate Pinning auditado em Eixo 2/resistenciaMitm.py (trabalho futuro).",
                },
                "summary": summary_map,
                "pinned_keys": {
                    "rogue_spki": rogue.rogue_pin,
                    "desktop_spki": keys_info.get("desktop_server_pin"),
                    "mobile_api_spki": keys_info.get("mobile_server_pin"),
                    "mobile_qr_spki": keys_info.get("mobile_qr_pin"),
                },
                "checks": [asdict(c) for c in checks],
                "rogue_requests": rogue.requests,
            }
            args.json_out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
            print(f"Relatório JSON salvo em: {args.json_out}")

        return 0 if verdict == "APROVADO" else 1
    finally:
        rogue.close()


if __name__ == "__main__":
    raise SystemExit(main())
