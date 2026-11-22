"""
Teste 3: Inviolabilidade da Máquina de Estados da API (Eixo 1)

Investiga o cumprimento estrito das transições do ciclo eleitoral no servidor
(CREATED -> STARTED -> CLOSED -> TALLIED) diante de requisições diretas fora
de sequência, saltos prematuros para apuração/exposição de cédulas e chave,
retrocessos de fase, injeção tardia de votos após o encerramento, bypass de
transporte criptográfico (TPM), adulteração de assinaturas, troca de máquina
física e abuso de controle de acesso (sem cabeçalho de autorização ou usuário
não criador), verificando invariância completa no banco de dados.
"""

from __future__ import annotations

import argparse
import base64
import datetime
import email
import email.header
import email.policy
import hashlib
import io
import json
import os
import re
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID

try:
    import psycopg2
except ImportError:  # pragma: no cover - opcional quando usando apenas SQLite
    psycopg2 = None  # type: ignore[assignment]


# ==============================================================================
# Configuração padrão do ensaio
# ==============================================================================
DEFAULT_BASE_URL = "http://127.0.0.1:8000"
BACKEND_DIR = Path("/home/debrito/Programação/votaai-backend")
DESKTOP_DIR = Path("/home/debrito/Programação/votaai-desktop")
SE_KEYS_PATH = BACKEND_DIR / "se_keys_info.json"
DEFAULT_ENV_PATH = BACKEND_DIR / ".env"
DEFAULT_SQLITE_PATH = BACKEND_DIR / "db.sqlite3"
DEFAULT_SENT_EMAILS_DIR = BACKEND_DIR / "sent_emails"
DEFAULT_CLIENT_KEY_PATH = DESKTOP_DIR / "app" / "resources" / "client_key.json"
DEFAULT_CLIENT_KEYS_DIR = DESKTOP_DIR / "app" / "resources" / ".client_keys"
DEFAULT_REGISTRATION_INFO_PATH = DESKTOP_DIR / "app" / "resources" / "registration_info.json"

VALID_STATES = ("CREATED", "STARTED", "CLOSED", "TALLIED")


# ==============================================================================
# Estruturas de dados do ensaio
# ==============================================================================
@dataclass
class AttackProbe:
    name: str
    endpoint: str
    http_status: int
    expected_statuses: tuple[int, ...]
    passed: bool
    detail: str
    response_preview: str = ""


@dataclass
class CheckResult:
    code: str
    title: str
    status: str  # "PASSOU" | "FALHOU" | "ALERTA" | "N/A"
    summary: str
    details: list[str] = field(default_factory=list)
    probes: list[AttackProbe] = field(default_factory=list)


@dataclass
class ElectionSnapshot:
    id: int
    title: str
    key_handle: str
    status: str
    start_datetime: str | None
    end_datetime: str | None
    private_key_present: bool
    private_key_hash: str | None
    created_by_id: int | None
    creator_machine_public_key: str | None
    votes_count: int
    ballot_tickets_count: int
    tally_count: int
    voted_count: int


# ==============================================================================
# Camada Criptográfica (compatível com SEDecryptMiddleware, SECryptoService e TPM)
# ==============================================================================
def _parse_rsa_public_key(raw_key: str) -> rsa.RSAPublicKey:
    """Converte PEM, DER Base64 ou blob Microsoft CNG (RSA1) em chave pública RSA."""
    text = raw_key.strip()
    if "-----BEGIN" in text:
        pub = serialization.load_pem_public_key(text.encode("utf-8"))
        if not isinstance(pub, rsa.RSAPublicKey):
            raise ValueError("Chave PEM carregada não é RSA.")
        return pub

    blob = base64.b64decode(text)
    if blob.startswith(b"RSA1"):
        if len(blob) < 24:
            raise ValueError("Blob CNG RSA1 truncado.")
        _, _, cb_exp, cb_mod, _, _ = struct.unpack("<IIIIII", blob[:24])
        if 24 + cb_exp + cb_mod > len(blob):
            raise ValueError("Tamanho inconsistente no blob CNG RSA1.")
        e = int.from_bytes(blob[24 : 24 + cb_exp], "big")
        n = int.from_bytes(blob[24 + cb_exp : 24 + cb_exp + cb_mod], "big")
        return rsa.RSAPublicNumbers(e, n).public_key()

    pub = serialization.load_der_public_key(blob)
    if not isinstance(pub, rsa.RSAPublicKey):
        raise ValueError("Chave DER carregada não é RSA.")
    return pub


def to_pem_public_key(raw_key: str | None) -> str:
    """Normaliza chave pública RSA para PEM SubjectPublicKeyInfo com LF."""
    if not raw_key or not raw_key.strip():
        return ""
    try:
        pub = _parse_rsa_public_key(raw_key)
        return (
            pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("utf-8")
            .strip()
            .replace("\r\n", "\n")
        )
    except Exception:
        return raw_key.strip().replace("\r\n", "\n")


def carregar_chave_servidor(key_name: str, se_keys_path: Path = SE_KEYS_PATH) -> rsa.RSAPublicKey:
    """Carrega chave pública do servidor (VotaAI_SecureKey_1 ou 2) a partir de se_keys_info.json."""
    if not se_keys_path.exists():
        raise FileNotFoundError(f"Arquivo de chaves do servidor não encontrado: {se_keys_path}")
    keys = json.loads(se_keys_path.read_text(encoding="utf-8"))
    if isinstance(keys, dict):
        keys = [keys]
    entry = next((k for k in keys if k.get("KeyName") == key_name), None)
    if not entry or not entry.get("PublicKeyBase64"):
        raise KeyError(f"Chave '{key_name}' não encontrada em {se_keys_path}.")
    return _parse_rsa_public_key(entry["PublicKeyBase64"])


def _get_machine_secret() -> bytes:
    """Replica a derivação PBKDF2-HMAC-SHA256 do fallback software de votaai-desktop."""
    try:
        machine_id = Path("/etc/machine-id").read_text(encoding="utf-8").strip()
    except OSError:
        machine_id = socket.gethostname()
    return hashlib.pbkdf2_hmac(
        "sha256",
        machine_id.encode("utf-8"),
        b"VotaAI-DesktopClient-KeyProtection-v1",
        iterations=200_000,
    )


def _load_encrypted_software_key(enc_path: Path) -> rsa.RSAPrivateKey:
    """Decifra chave privada RSA armazenada em .enc pelo fallback software do Desktop."""
    raw = enc_path.read_bytes()
    if len(raw) < 28:
        raise ValueError(f"Arquivo de chave cifrada inválido: {enc_path}")
    iv, ciphertext = raw[:12], raw[12:]
    pem_buf = bytearray(AESGCM(_get_machine_secret()).decrypt(iv, ciphertext, b"VotaAI-client-key-aad"))
    try:
        priv = serialization.load_pem_private_key(bytes(pem_buf), password=None)
    finally:
        for i in range(len(pem_buf)):
            pem_buf[i] = 0
    if not isinstance(priv, rsa.RSAPrivateKey):
        raise ValueError(f"Chave decifrada em {enc_path} não é RSA.")
    return priv


class MachineSignerBase:
    """Interface comum para assinatura/decifragem da máquina cliente Desktop."""

    public_pem: str
    backend_label: str

    def sign(self, data: bytes) -> str:
        raise NotImplementedError

    def decrypt(self, cipher_bytes: bytes) -> bytes:
        raise NotImplementedError


class EphemeralMachineSigner(MachineSignerBase):
    """Chave RSA-2048 efêmera em memória usada para simular uma máquina intrusa/não-criadora."""

    def __init__(self, label: str = "Ephemeral-Rogue-RSA2048") -> None:
        self._priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_pem = (
            self._priv.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("utf-8")
        )
        self.backend_label = label

    def sign(self, data: bytes) -> str:
        sig = self._priv.sign(
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return base64.b64encode(sig).decode("utf-8")

    def decrypt(self, cipher_bytes: bytes) -> bytes:
        return self._priv.decrypt(cipher_bytes, padding.PKCS1v15())


class DesktopMachineSigner(MachineSignerBase):
    """
    Reproduz a assinatura e decifragem da máquina Desktop configurada em client_key.json:
    usa o TPM 2.0 (tpm2_sign / tpm2_rsadecrypt) quando disponível, ou o arquivo .enc local.
    """

    def __init__(
        self,
        client_key_path: Path = DEFAULT_CLIENT_KEY_PATH,
        client_keys_dir: Path = DEFAULT_CLIENT_KEYS_DIR,
    ) -> None:
        if not client_key_path.exists():
            raise FileNotFoundError(f"client_key.json não encontrado em {client_key_path}")
        meta = json.loads(client_key_path.read_text(encoding="utf-8"))
        self.key_name = str(meta.get("KeyName") or "VotaAI_DesktopClient_Key")
        self.storage = str(meta.get("Storage") or "").strip().lower()
        self.tpm_handle = meta.get("TPMHandle")
        raw_pub = meta.get("PublicKeyPEM") or meta.get("PublicKeyBase64")
        if not raw_pub:
            raise ValueError(f"Chave pública ausente em {client_key_path}")
        self.public_pem = to_pem_public_key(str(raw_pub))
        self._pub_obj = _parse_rsa_public_key(self.public_pem)
        self._client_keys_dir = client_keys_dir
        self._sw_priv: rsa.RSAPrivateKey | None = None
        self._use_tpm = self._probe_tpm_handle()

        if self._use_tpm:
            self.backend_label = f"TPM 2.0 (handle {self.tpm_handle})"
        else:
            self._sw_priv = self._load_matching_software_key()
            self.backend_label = f"Software cifrado (.enc: {self.key_name})"

    def _probe_tpm_handle(self) -> bool:
        if self.storage != "tpm2" or not self.tpm_handle:
            return False
        try:
            res = subprocess.run(
                ["tpm2_getcap", "handles-persistent"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if res.returncode != 0:
                return False
            return str(self.tpm_handle).lower() in res.stdout.lower()
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return False

    def _load_matching_software_key(self) -> rsa.RSAPrivateKey:
        clean_name = "".join(c for c in self.key_name if c.isalnum() or c in ("_", "-"))
        enc_path = self._client_keys_dir / f"{clean_name}.enc"
        if not enc_path.exists():
            raise RuntimeError(
                f"TPM handle '{self.tpm_handle}' indisponível e chave software '{enc_path}' não encontrada."
            )
        priv = _load_encrypted_software_key(enc_path)
        derived_pem = (
            priv.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("utf-8")
            .strip()
            .replace("\r\n", "\n")
        )
        if derived_pem != self.public_pem.strip():
            raise RuntimeError(
                f"TPM 2.0 inacessível e a chave software '{enc_path}' não corresponde à PublicKeyPEM de client_key.json."
            )
        return priv

    def sign(self, data: bytes) -> str:
        if self._use_tpm and self.tpm_handle:
            try:
                with tempfile.TemporaryDirectory() as tmpdir:
                    data_path = os.path.join(tmpdir, "data.bin")
                    sig_path = os.path.join(tmpdir, "sig.bin")
                    Path(data_path).write_bytes(data)
                    res = subprocess.run(
                        [
                            "tpm2_sign",
                            "-c",
                            str(self.tpm_handle),
                            "-g",
                            "sha256",
                            "-s",
                            "rsapss",
                            "-f",
                            "plain",
                            "-o",
                            sig_path,
                            data_path,
                        ],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    if res.returncode == 0 and Path(sig_path).exists():
                        return base64.b64encode(Path(sig_path).read_bytes()).decode("utf-8")
                    raise RuntimeError(res.stderr.strip() or f"returncode={res.returncode}")
            except Exception as tpm_exc:
                if self._sw_priv is None:
                    try:
                        self._sw_priv = self._load_matching_software_key()
                        self._use_tpm = False
                        self.backend_label = f"Software cifrado (.enc fallback após TPM erro: {tpm_exc})"
                    except Exception as sw_exc:
                        raise RuntimeError(
                            f"Falha ao assinar no TPM ({tpm_exc}) e sem fallback compatível ({sw_exc})."
                        ) from tpm_exc

        if self._sw_priv is None:
            raise RuntimeError("Nenhuma chave privada disponível para assinatura.")
        sig = self._sw_priv.sign(
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return base64.b64encode(sig).decode("utf-8")

    def decrypt(self, cipher_bytes: bytes) -> bytes:
        if self._use_tpm and self.tpm_handle:
            try:
                with tempfile.TemporaryDirectory() as tmpdir:
                    enc_path = os.path.join(tmpdir, "enc.bin")
                    dec_path = os.path.join(tmpdir, "dec.bin")
                    Path(enc_path).write_bytes(cipher_bytes)
                    res = subprocess.run(
                        [
                            "tpm2_rsadecrypt",
                            "-c",
                            str(self.tpm_handle),
                            "-s",
                            "rsaes",
                            "-o",
                            dec_path,
                            enc_path,
                        ],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    if res.returncode == 0 and Path(dec_path).exists():
                        return Path(dec_path).read_bytes()
                    raise RuntimeError(res.stderr.strip() or f"returncode={res.returncode}")
            except Exception as tpm_exc:
                if self._sw_priv is None:
                    try:
                        self._sw_priv = self._load_matching_software_key()
                        self._use_tpm = False
                    except Exception:
                        raise RuntimeError(f"Falha ao decifrar no TPM: {tpm_exc}") from tpm_exc

        if self._sw_priv is None:
            raise RuntimeError("Nenhuma chave privada disponível para decifragem.")
        return self._sw_priv.decrypt(cipher_bytes, padding.PKCS1v15())


def cifrar_envelope(pub_key: rsa.RSAPublicKey, payload: dict[str, Any]) -> dict[str, str]:
    """Cifra payload no formato híbrido AES-256-GCM + RSA PKCS#1 v1.5 esperado por SEDecryptMiddleware."""
    aes_key, iv = os.urandom(32), os.urandom(12)
    ct_tag = AESGCM(aes_key).encrypt(iv, json.dumps(payload, ensure_ascii=False).encode("utf-8"), None)
    return {
        "encrypted_payload": base64.b64encode(ct_tag[:-16]).decode("utf-8"),
        "encrypted_aes_key": base64.b64encode(pub_key.encrypt(aes_key, padding.PKCS1v15())).decode("utf-8"),
        "iv": base64.b64encode(iv).decode("utf-8"),
        "tag": base64.b64encode(ct_tag[-16:]).decode("utf-8"),
    }


def decifrar_envelope_dict(decrypt_fn: Any, data: dict[str, Any]) -> Any:
    """Descriptografa um envelope híbrido usando callable `decrypt_fn(bytes) -> bytes` ou RSAPrivateKey."""
    enc_aes = base64.b64decode(data["encrypted_aes_key"])
    if isinstance(decrypt_fn, rsa.RSAPrivateKey):
        aes_key = decrypt_fn.decrypt(enc_aes, padding.PKCS1v15())
    elif callable(decrypt_fn):
        aes_key = decrypt_fn(enc_aes)
    else:
        raise TypeError("decrypt_fn deve ser RSAPrivateKey ou callable.")
    plain = AESGCM(aes_key[:32]).decrypt(
        base64.b64decode(data["iv"]),
        base64.b64decode(data["encrypted_payload"]) + base64.b64decode(data["tag"]),
        None,
    )
    return json.loads(plain.decode("utf-8"))


def decifrar_resposta(decrypt_fn: Any, raw_text: str) -> Any:
    """Descriptografa resposta da API quando em envelope híbrido, sem falhar caso ilegível."""
    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError:
        return raw_text

    if isinstance(data, dict) and {"encrypted_payload", "encrypted_aes_key", "iv", "tag"} <= data.keys():
        if decrypt_fn is None:
            return {"_encrypted_unreadable": True, "keys": sorted(data.keys())}
        try:
            return decifrar_envelope_dict(decrypt_fn, data)
        except Exception as exc:
            return {"_encrypted_unreadable": True, "error": str(exc)}
    return data


def assinar_payload_canonico(signer: MachineSignerBase, payload: dict[str, Any]) -> str:
    """Assina o JSON canônico do payload (excluindo 'signature'), padrão Sign-then-Encrypt."""
    clean = {k: v for k, v in payload.items() if k != "signature"}
    canonical = json.dumps(clean, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return signer.sign(canonical)


def assinar_eleicao(election_priv: rsa.RSAPrivateKey, payload: dict[str, Any]) -> str:
    """Assina comando de eleição (start/close) removendo election_signature, signature e machine_public_key."""
    clean = dict(payload)
    clean.pop("election_signature", None)
    clean.pop("signature", None)
    clean.pop("machine_public_key", None)
    canonical = json.dumps(clean, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    sig = election_priv.sign(canonical, padding.PKCS1v15(), hashes.SHA256())
    return base64.b64encode(sig).decode("utf-8")


def verificar_assinatura_rsa(pub_key: rsa.RSAPublicKey, data: bytes, signature_b64: str) -> bool:
    """Verifica assinatura RSA-PSS ou PKCS1v15 SHA-256 (compatível com SECryptoService)."""
    try:
        sig_bytes = base64.b64decode(signature_b64.strip())
    except Exception:
        return False

    for pad in (
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.AUTO),
        padding.PKCS1v15(),
    ):
        try:
            pub_key.verify(sig_bytes, data, pad, hashes.SHA256())
            return True
        except Exception:
            continue
    return False


# ==============================================================================
# Auxiliares Mobile (StrongBox + Cédula) e Apuração Canônica
# ==============================================================================
def gerar_certificado_strongbox(dev_priv: rsa.RSAPrivateKey, challenge: str) -> str:
    """Gera certificado X.509 autoassinado com extensão de atestação Android KeyStore."""
    ch = challenge.encode("utf-8")
    inner = b"\x02\x01\x03\x0a\x01\x02\x02\x01\x04\x0a\x01\x02\x04" + bytes([len(ch)]) + ch
    ext_val = b"\x30" + bytes([len(inner)]) + inner
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "StrongBox Test CA")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(dev_priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"), ext_val),
            critical=False,
        )
        .sign(dev_priv, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def _post_mobile_envelope(
    base_url: str,
    path: str,
    api_pub_mobile: rsa.RSAPublicKey,
    dev_priv: rsa.RSAPrivateKey,
    payload: dict[str, Any],
) -> tuple[int, Any]:
    env = cifrar_envelope(api_pub_mobile, payload)
    resp = requests.post(f"{base_url.rstrip('/')}{path}", json=env, timeout=15)
    return resp.status_code, decifrar_resposta(dev_priv, resp.text)


def solicitar_cedula_mobile(
    base_url: str,
    api_pub_mobile: rsa.RSAPublicKey,
    raw_token: str,
    choice_index: int = 0,
) -> tuple[int, Any, dict[str, Any] | None]:
    """Solicita cédula via /api/vote/request/ e prepara pacote cifrado/assinado para /cast/."""
    dev_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    dev_pub_pem = (
        dev_priv.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    nonce_req = f"nonce-req-{uuid.uuid4().hex[:12]}"
    code, body = _post_mobile_envelope(
        base_url,
        "/api/vote/request/",
        api_pub_mobile,
        dev_priv,
        {
            "token": raw_token,
            "machine_public_key": dev_pub_pem,
            "attestation_certificates": [gerar_certificado_strongbox(dev_priv, nonce_req)],
            "nonce": nonce_req,
        },
    )
    if code != 200 or not isinstance(body, dict) or "id_voto" not in body:
        return code, body, None

    id_voto = body["id_voto"]
    election = body["election"]
    election_pub = serialization.load_pem_public_key(election["public_key"].encode("utf-8"))
    if not isinstance(election_pub, rsa.RSAPublicKey):
        raise RuntimeError("Chave pública da eleição recebida no mobile não é RSA.")

    choices: dict[str, int] = {}
    for q in election.get("questions", []):
        options = q.get("options", [])
        if not options:
            continue
        non_blank = [opt for opt in options if opt.get("label") not in ("Branco", "Nulo")]
        pool = non_blank or options
        selected = pool[choice_index % len(pool)]
        choices[str(q["id"])] = selected["id"]

    ballot_payload = {"election_id": election["id"], "choices": choices}
    ballot_plain = json.dumps(ballot_payload, separators=(",", ":")).encode("utf-8")
    if len(ballot_plain) > 200:
        pacote_cifrado = json.dumps(cifrar_envelope(election_pub, ballot_payload), separators=(",", ":"))
    else:
        cipher_bytes = election_pub.encrypt(ballot_plain, padding.PKCS1v15())
        pacote_cifrado = base64.b64encode(cipher_bytes).decode("utf-8")

    content = json.dumps({"id_voto": id_voto, "pacote_cifrado": pacote_cifrado}, separators=(",", ":"))
    signature = base64.b64encode(
        dev_priv.sign(content.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256())
    ).decode("utf-8")

    prepared = {
        "raw_token": raw_token,
        "dev_priv": dev_priv,
        "dev_pub_pem": dev_pub_pem,
        "id_voto": id_voto,
        "content": content,
        "signature": signature,
    }
    return code, body, prepared


def depositar_voto_mobile(
    base_url: str,
    api_pub_mobile: rsa.RSAPublicKey,
    prepared: dict[str, Any],
) -> tuple[int, Any]:
    """Submete uma cédula previamente preparada para /api/vote/cast/."""
    return _post_mobile_envelope(
        base_url,
        "/api/vote/cast/",
        api_pub_mobile,
        prepared["dev_priv"],
        {
            "token": prepared["raw_token"],
            "machine_public_key": prepared["dev_pub_pem"],
            "content": prepared["content"],
            "id_voto": prepared["id_voto"],
            "nonce": f"nonce-cast-{uuid.uuid4().hex[:12]}",
            "signature": prepared["signature"],
        },
    )


def decifrar_cedula(election_priv: rsa.RSAPrivateKey, content_str: str) -> dict[str, Any]:
    """Decifra uma cédula da urna usando a chave privada da eleição (camada dupla, híbrido ou RSA direto)."""
    pacote = content_str.strip()
    try:
        outer = json.loads(pacote)
        if isinstance(outer, dict) and "pacote_cifrado" in outer:
            pacote = str(outer["pacote_cifrado"]).strip()
    except json.JSONDecodeError:
        pass

    try:
        maybe_env = json.loads(pacote)
        if isinstance(maybe_env, dict) and {"encrypted_payload", "encrypted_aes_key", "iv", "tag"} <= maybe_env.keys():
            res = decifrar_envelope_dict(election_priv, maybe_env)
            return res if isinstance(res, dict) else {"value": res}
    except Exception:
        pass

    cipher_bytes = base64.b64decode(pacote)
    try:
        plain = election_priv.decrypt(cipher_bytes, padding.PKCS1v15())
    except Exception:
        plain = election_priv.decrypt(
            cipher_bytes,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )
    parsed = json.loads(plain.decode("utf-8"))
    return parsed if isinstance(parsed, dict) else {"value": parsed}


def computar_apuracao_canonica(
    raw_votes: list[dict[str, Any]],
    questions_meta: list[dict[str, Any]],
    total_voters: int,
    key_handle: str,
    election_priv: rsa.RSAPrivateKey,
) -> tuple[dict[str, Any], str]:
    """Replica TallyElectionController.tally_votes_core para calcular results e tally_hash SHA-256."""
    question_map: dict[Any, str] = {}
    option_map: dict[Any, str] = {}
    structured_questions: list[dict[str, Any]] = []

    for q_info in questions_meta:
        q_id = q_info.get("id")
        q_text = str(q_info.get("question") or f"Pergunta {q_id}")
        question_map[str(q_id)] = q_text
        question_map[q_id] = q_text
        opts_list = []
        for opt_info in q_info.get("options", []):
            opt_id = opt_info.get("id")
            opt_label = str(opt_info.get("label") or f"Opção {opt_id}")
            option_map[str(opt_id)] = opt_label
            option_map[opt_id] = opt_label
            opts_list.append({"id": opt_id, "label": opt_label, "votes": 0, "percentage": 0.0})
        structured_questions.append({"id": q_id, "question": q_text, "total_votes": 0, "options": opts_list})

    results: dict[str, dict[str, int]] = {}
    decrypted_ballots: list[dict[str, Any]] = []
    for vote_item in raw_votes:
        receipt = vote_item.get("id_generated", "")
        ballot_obj = decifrar_cedula(election_priv, str(vote_item.get("content", "")))
        if isinstance(ballot_obj.get("choices"), dict):
            for q_key, opt_val in ballot_obj["choices"].items():
                q_name = question_map.get(str(q_key), question_map.get(q_key, f"Pergunta {q_key}"))
                opt_name = option_map.get(str(opt_val), option_map.get(opt_val, str(opt_val)))
                results.setdefault(q_name, {})
                results[q_name][opt_name] = results[q_name].get(opt_name, 0) + 1
        decrypted_ballots.append({"receipt": receipt, "ballot": ballot_obj})

    for q_entry in structured_questions:
        q_counts = results.get(q_entry["question"], {})
        q_total = sum(q_counts.values())
        q_entry["total_votes"] = q_total
        for opt_entry in q_entry["options"]:
            c = q_counts.get(opt_entry["label"], 0)
            opt_entry["votes"] = c
            opt_entry["percentage"] = round((c / q_total) * 100, 2) if q_total > 0 else 0.0

    abstention_count = max(0, total_voters - len(raw_votes))
    abstention_percentage = round((abstention_count / total_voters) * 100, 2) if total_voters > 0 else 0.0
    final_results: dict[str, Any] = dict(results)
    final_results.update(
        {
            "summary": results,
            "questions": structured_questions,
            "total_votos": len(raw_votes),
            "total_voters": total_voters,
            "abstention_count": abstention_count,
            "abstention_percentage": abstention_percentage,
        }
    )

    canonical_audit = {
        "keyHandle": key_handle,
        "total_votos": len(raw_votes),
        "results": final_results,
        "decrypted_ballots": decrypted_ballots,
    }
    canonical_json = json.dumps(canonical_audit, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    tally_hash = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
    return final_results, tally_hash


def _decode_mime_header(value: str | None) -> str:
    if not value:
        return ""
    parts = []
    for chunk, charset in email.header.decode_header(value):
        if isinstance(chunk, bytes):
            parts.append(chunk.decode(charset or "utf-8", errors="replace"))
        else:
            parts.append(chunk)
    return "".join(parts)


def capturar_tokens_email(
    sent_emails_dir: Path,
    election_title: str,
    since_ts: float,
) -> dict[str, str]:
    """Extrai tokens de votação dos logs gerados em sent_emails/ após o início da eleição."""
    tokens_by_email: dict[str, str] = {}
    if not sent_emails_dir.is_dir():
        return tokens_by_email

    for path in sorted(sent_emails_dir.glob("*.log")):
        try:
            st = path.stat()
        except OSError:
            continue
        if st.st_mtime < since_ts - 2.0:
            continue
        try:
            msg = email.message_from_bytes(path.read_bytes(), policy=email.policy.default)
        except Exception:
            continue

        subject = _decode_mime_header(msg.get("Subject"))
        to_hdr = _decode_mime_header(msg.get("To"))
        body_parts: list[str] = []
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() in ("text/plain", "text/html"):
                    try:
                        body_parts.append(part.get_content())
                    except Exception:
                        pass
        else:
            try:
                body_parts.append(msg.get_content())
            except Exception:
                pass
        body_text = "\n".join(str(p) for p in body_parts)
        if election_title not in subject and election_title not in body_text:
            continue

        found_tokens = re.findall(r"token=([A-Za-z0-9_-]{20,})", body_text)
        email_match = re.search(r"([A-Za-z0-9_.+-]+@[A-Za-z0-9-]+\.[A-Za-z0-9-.]+)", to_hdr)
        if found_tokens and email_match:
            tokens_by_email[email_match.group(1).lower()] = found_tokens[0]
    return tokens_by_email


# ==============================================================================
# Adaptador de Banco de Dados Somente Leitura (PostgreSQL e SQLite)
# ==============================================================================
def ler_dotenv(env_path: Path) -> dict[str, str]:
    """Lê variáveis de um arquivo .env simples, ignorando comentários e linhas vazias."""
    env: dict[str, str] = {}
    if not env_path.exists():
        return env
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
            val = val[1:-1]
        env[key] = val
    return env


class DBAdapter:
    """Abstração somente leitura para consultas SQL diretas em PostgreSQL ou SQLite."""

    def __init__(self, backend: str, conn: Any, description: str, notes: list[str] | None = None) -> None:
        self.backend = backend
        self.conn = conn
        self.description = description
        self.notes = notes or []

    @classmethod
    def connect(
        cls,
        db_url: str | None = None,
        sqlite_path: Path | None = None,
        env_path: Path = DEFAULT_ENV_PATH,
    ) -> "DBAdapter":
        notes: list[str] = []
        dsn = db_url or os.environ.get("DATABASE_URL")

        if dsn:
            if psycopg2 is None:
                raise RuntimeError("psycopg2 não está instalado para conectar ao PostgreSQL.")
            conn = psycopg2.connect(dsn)
            conn.set_session(readonly=True, autocommit=True)
            safe_dsn = re.sub(r":([^:@/]+)@", ":***@", dsn)
            return cls("postgresql", conn, f"PostgreSQL ({safe_dsn})", notes)

        if sqlite_path is not None:
            if not sqlite_path.exists():
                raise FileNotFoundError(f"Banco SQLite não encontrado: {sqlite_path}")
            conn = sqlite3.connect(f"file:{sqlite_path}?mode=ro", uri=True)
            return cls("sqlite", conn, f"SQLite ({sqlite_path})", notes)

        env = ler_dotenv(env_path)
        db_name = env.get("DB_NAME", "").strip()
        if db_name:
            if psycopg2 is None:
                raise RuntimeError("DB_NAME definido no .env, mas psycopg2 não está instalado.")
            user = env.get("DB_USER", "postgres").strip() or "postgres"
            password = env.get("DB_PASSWORD", "postgres")
            host = env.get("DB_HOST", "db").strip() or "db"
            port = int((env.get("DB_PORT", "5432").strip() or "5432"))
            try:
                conn = psycopg2.connect(dbname=db_name, user=user, password=password, host=host, port=port)
            except psycopg2.OperationalError:
                if host == "db":
                    notes.append("Host 'db' inacessível fora do container; reconectado em 127.0.0.1.")
                    host = "127.0.0.1"
                    conn = psycopg2.connect(dbname=db_name, user=user, password=password, host=host, port=port)
                else:
                    raise
            conn.set_session(readonly=True, autocommit=True)
            return cls("postgresql", conn, f"PostgreSQL ({user}@{host}:{port}/{db_name})", notes)

        if not DEFAULT_SQLITE_PATH.exists():
            raise FileNotFoundError(
                f"Nem DB_NAME no .env nem SQLite padrão encontrado em {DEFAULT_SQLITE_PATH}."
            )
        notes.append(
            f".env ({env_path}) sem DB_NAME configurado; usando SQLite local. "
            "Para auditar PostgreSQL, defina DB_NAME no .env ou passe --db-url."
        )
        conn = sqlite3.connect(f"file:{DEFAULT_SQLITE_PATH}?mode=ro", uri=True)
        return cls("sqlite", conn, f"SQLite ({DEFAULT_SQLITE_PATH})", notes)

    def close(self) -> None:
        self.conn.close()

    def query_all(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        cur = self.conn.cursor()
        try:
            final_sql = sql.replace("%s", "?") if self.backend == "sqlite" else sql
            cur.execute(final_sql, params)
            cols = [desc[0] for desc in (cur.description or [])]
            return [dict(zip(cols, row)) for row in cur.fetchall()]
        finally:
            cur.close()

    def table_exists(self, table_name: str) -> bool:
        if self.backend == "postgresql":
            rows = self.query_all(
                """
                SELECT 1
                FROM information_schema.tables
                WHERE table_schema = 'public' AND table_name = %s
                LIMIT 1
                """,
                (table_name,),
            )
            return bool(rows)
        rows = self.query_all(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name = %s LIMIT 1",
            (table_name,),
        )
        return bool(rows)


def capturar_snapshot_eleicao(db: DBAdapter, election_id: int) -> ElectionSnapshot:
    """Captura foto instantânea somente leitura da eleição e tabelas associadas."""
    rows = db.query_all(
        """
        SELECT e.id, e.title, e.key_handle, e.status, e.start_datetime, e.end_datetime,
               e.private_key, e.created_by_id, u.machine_public_key AS creator_machine_public_key
        FROM "Domain_election" e
        LEFT JOIN "Domain_user" u ON u.id = e.created_by_id
        WHERE e.id = %s
        """,
        (election_id,),
    )
    if not rows:
        raise LookupError(f"Eleição #{election_id} não encontrada no banco ({db.description}).")
    row = rows[0]

    priv_val = row.get("private_key") or ""
    priv_present = bool(str(priv_val).strip())
    priv_hash = hashlib.sha256(str(priv_val).strip().encode("utf-8")).hexdigest()[:16] if priv_present else None

    votes_count = db.query_all(
        'SELECT COUNT(*) AS c FROM "Domain_vote" WHERE election_id = %s',
        (election_id,),
    )[0]["c"]
    tickets_count = db.query_all(
        'SELECT COUNT(*) AS c FROM "Domain_ballotticket" WHERE election_id = %s',
        (election_id,),
    )[0]["c"]
    tally_count = db.query_all(
        'SELECT COUNT(*) AS c FROM "Domain_tally" WHERE election_id = %s',
        (election_id,),
    )[0]["c"]
    voted_count = db.query_all(
        'SELECT COUNT(*) AS c FROM "Domain_electoralcollege" WHERE election_id = %s AND has_voted = %s',
        (election_id, True),
    )[0]["c"]

    return ElectionSnapshot(
        id=int(row["id"]),
        title=str(row["title"]),
        key_handle=str(row["key_handle"]),
        status=str(row["status"]),
        start_datetime=str(row["start_datetime"]) if row.get("start_datetime") is not None else None,
        end_datetime=str(row["end_datetime"]) if row.get("end_datetime") is not None else None,
        private_key_present=priv_present,
        private_key_hash=priv_hash,
        created_by_id=int(row["created_by_id"]) if row.get("created_by_id") is not None else None,
        creator_machine_public_key=(
            to_pem_public_key(str(row["creator_machine_public_key"]))
            if row.get("creator_machine_public_key")
            else None
        ),
        votes_count=int(votes_count),
        ballot_tickets_count=int(tickets_count),
        tally_count=int(tally_count),
        voted_count=int(voted_count),
    )


def verificar_invariancia(antes: ElectionSnapshot, depois: ElectionSnapshot, fase: str) -> list[str]:
    """Detecta qualquer mutação indevida no estado persistido após bateria de ataques."""
    diffs: list[str] = []
    checks = (
        ("status", antes.status, depois.status),
        ("start_datetime", antes.start_datetime, depois.start_datetime),
        ("end_datetime", antes.end_datetime, depois.end_datetime),
        ("private_key_present", antes.private_key_present, depois.private_key_present),
        ("private_key_hash", antes.private_key_hash, depois.private_key_hash),
        ("votes_count", antes.votes_count, depois.votes_count),
        ("ballot_tickets_count", antes.ballot_tickets_count, depois.ballot_tickets_count),
        ("tally_count", antes.tally_count, depois.tally_count),
        ("voted_count", antes.voted_count, depois.voted_count),
    )
    for field_name, old_val, new_val in checks:
        if old_val != new_val:
            diffs.append(f"[{fase}] Mutação colateral em '{field_name}': {old_val!r} -> {new_val!r}")
    return diffs


def encontrar_usuario_desktop(db: DBAdapter, machine_pub_pem: str) -> dict[str, Any] | None:
    """Verifica na tabela Domain_user se existe conta ativa vinculada à chave da máquina Desktop."""
    if not db.table_exists("Domain_user"):
        return None
    norm_target = to_pem_public_key(machine_pub_pem)
    rows = db.query_all('SELECT id, username, email, is_active, device_id, machine_public_key FROM "Domain_user"')
    for r in rows:
        db_key = r.get("machine_public_key")
        if db_key and to_pem_public_key(str(db_key)) == norm_target:
            return r
    return None


def autenticar_admin_desktop(
    base_url: str,
    api_pub_desktop: rsa.RSAPublicKey,
    signer: MachineSignerBase,
    db: DBAdapter,
    registration_info_path: Path = DEFAULT_REGISTRATION_INFO_PATH,
    admin_email: str | None = None,
    admin_password: str | None = None,
    admin_totp: str | None = None,
    device_id: str | None = None,
) -> str:
    """Autentica o administrador via POST /api/auth/login/ usando assinatura TPM e retorna o token Knox."""
    if not admin_password or not admin_totp:
        raise RuntimeError(
            "Credenciais incompletas: informe --admin-password e --admin-totp (ou passe --auth-token)."
        )

    creator = encontrar_usuario_desktop(db, signer.public_pem)
    reg_info: dict[str, Any] = {}
    if registration_info_path.exists():
        try:
            reg_info = json.loads(registration_info_path.read_text(encoding="utf-8"))
        except Exception:
            reg_info = {}

    email_val = (
        admin_email
        or (creator.get("email") if creator else None)
        or reg_info.get("email")
        or ""
    ).strip()
    dev_val = (
        device_id
        or (creator.get("device_id") if creator else None)
        or reg_info.get("device_id")
        or ""
    ).strip()
    if not email_val:
        raise RuntimeError("E-mail do administrador não encontrado; informe --admin-email.")
    if not dev_val:
        raise RuntimeError("device_id da máquina não encontrado; informe --device-id.")

    code, body = _post_desktop(
        base_url,
        "/api/auth/login/",
        api_pub_desktop,
        {
            "username": email_val,
            "password": admin_password,
            "totp_code": admin_totp.strip(),
            "device_id": dev_val,
        },
        signer=signer,
    )
    if code != 200 or not isinstance(body, dict) or not body.get("token"):
        raise RuntimeError(f"Falha ao autenticar administrador em /api/auth/login/ (HTTP {code}): {body}")
    return str(body["token"])


# ==============================================================================
# Utilitários HTTP / Envelopes Desktop para Probes
# ==============================================================================
def _build_desktop_envelope(
    api_pub_desktop: rsa.RSAPublicKey,
    payload: dict[str, Any],
    signer: MachineSignerBase | None = None,
    machine_pub_pem: str | None = None,
    tamper_signature: bool = False,
) -> dict[str, str]:
    body = dict(payload)
    pub_pem = machine_pub_pem if machine_pub_pem is not None else (signer.public_pem if signer else "")
    if pub_pem:
        body["machine_public_key"] = pub_pem

    if tamper_signature:
        body["signature"] = base64.b64encode(b"assinatura_envelope_adulterada_fsm_test").decode("utf-8")
    elif signer is not None and "signature" not in body:
        body["signature"] = assinar_payload_canonico(signer, body)

    return cifrar_envelope(api_pub_desktop, body)


def _post_desktop(
    base_url: str,
    path: str,
    api_pub_desktop: rsa.RSAPublicKey,
    payload: dict[str, Any],
    *,
    signer: MachineSignerBase | None = None,
    machine_pub_pem: str | None = None,
    tamper_signature: bool = False,
    auth_token: str | None = None,
    plaintext: bool = False,
) -> tuple[int, Any]:
    headers = {"Content-Type": "application/json"}
    if auth_token:
        headers["Authorization"] = f"Token {auth_token}"

    if plaintext:
        req_body: dict[str, Any] = dict(payload)
        if machine_pub_pem:
            req_body["machine_public_key"] = machine_pub_pem
        decrypt_fn = None
    else:
        req_body = _build_desktop_envelope(
            api_pub_desktop,
            payload,
            signer=signer,
            machine_pub_pem=machine_pub_pem,
            tamper_signature=tamper_signature,
        )
        decrypt_fn = signer.decrypt if signer is not None else None

    resp = requests.post(
        f"{base_url.rstrip('/')}{path}",
        json=req_body,
        headers=headers,
        timeout=15,
    )
    return resp.status_code, decifrar_resposta(decrypt_fn, resp.text)


def _preview(body: Any) -> str:
    txt = json.dumps(body, ensure_ascii=False) if isinstance(body, (dict, list)) else str(body)
    return txt[:160] + ("..." if len(txt) > 160 else "")


def _probe_desktop(
    name: str,
    path: str,
    expected_statuses: tuple[int, ...],
    base_url: str,
    api_pub_desktop: rsa.RSAPublicKey,
    payload: dict[str, Any],
    **kwargs: Any,
) -> AttackProbe:
    code, body = _post_desktop(base_url, path, api_pub_desktop, payload, **kwargs)
    passed = code in expected_statuses
    return AttackProbe(
        name=name,
        endpoint=f"POST {path}",
        http_status=code,
        expected_statuses=expected_statuses,
        passed=passed,
        detail=f"HTTP {code} (esperado {list(expected_statuses)})",
        response_preview=_preview(body),
    )


def _probe_get_status(
    name: str,
    path: str,
    expected_statuses: tuple[int, ...],
    base_url: str,
) -> tuple[AttackProbe, Any]:
    resp = requests.get(f"{base_url.rstrip('/')}{path}", timeout=15)
    try:
        parsed: Any = resp.json()
    except Exception:
        parsed = resp.text[:160]
    passed = resp.status_code in expected_statuses
    probe = AttackProbe(
        name=name,
        endpoint=f"GET {path}",
        http_status=resp.status_code,
        expected_statuses=expected_statuses,
        passed=passed,
        detail=f"HTTP {resp.status_code} (esperado {list(expected_statuses)})",
        response_preview=f"bytes={len(resp.content)}" if isinstance(parsed, str) and resp.headers.get("Content-Type") == "application/zip" else _preview(parsed),
    )
    return probe, parsed


def _build_check_from_probes(
    code: str,
    title: str,
    probes: list[AttackProbe],
    pass_summary: str,
    extra_notes: list[str] | None = None,
    has_alert: bool = False,
) -> CheckResult:
    failed = [p for p in probes if not p.passed]
    details: list[str] = []
    for p in probes:
        tag = "OK" if p.passed else "VIOLAÇÃO"
        details.append(f"[{tag}] {p.name} -> {p.endpoint} | {p.detail} | resp={p.response_preview}")
    if extra_notes:
        details.extend(extra_notes)

    if failed:
        return CheckResult(
            code=code,
            title=title,
            status="FALHOU",
            summary=f"{len(failed)}/{len(probes)} verificação(ões) falharam (ex.: {failed[0].name}).",
            details=details,
            probes=probes,
        )
    if has_alert:
        return CheckResult(
            code=code,
            title=title,
            status="ALERTA",
            summary=f"{len(probes)} verificação(ões) executadas com alerta(s) de autorização.",
            details=details,
            probes=probes,
        )
    return CheckResult(
        code=code,
        title=title,
        status="PASSOU",
        summary=f"{pass_summary} ({len(probes)}/{len(probes)} bloqueios/validações conformes).",
        details=details,
        probes=probes,
    )


def _dummy_rsa_private_pem() -> str:
    """Gera chave privada RSA-2048 sintaticamente válida para testar validação de fase/chave."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


# ==============================================================================
# Baterias de Auditoria da Máquina de Estados (M1 - M6)
# ==============================================================================
def auditar_fase_created(
    base_url: str,
    snap: ElectionSnapshot,
    api_pub_desktop: rsa.RSAPublicKey,
    api_pub_mobile: rsa.RSAPublicKey,
    creator_signer: MachineSignerBase | None,
    creator_pub_pem: str | None,
    election_priv: rsa.RSAPrivateKey | None,
    vote_token: str | None,
    auth_token: str | None,
) -> CheckResult:
    """M1: Segregação da fase CREATED (bloqueia close, tally, exposição pública e voto)."""
    probes: list[AttackProbe] = []
    extra_notes: list[str] = []
    pub_pem = creator_pub_pem or snap.creator_machine_public_key
    admin_reject_statuses = (400, 403) if auth_token else (400, 401, 403)
    if not auth_token:
        extra_notes.append(
            "Executado sem --auth-token; rotas administrativas rejeitam com HTTP 401 antes da validação de fase. "
            "Passe --auth-token (ou --admin-password + --admin-totp) para validar transições como administrador autenticado."
        )

    # 1. Tentar fechar eleição ainda CREATED
    close_payload: dict[str, Any] = {
        "msg": "CLOSE_ELECTION",
        "keyHandle": snap.key_handle,
        "nonceClient3": f"fsm-m1-close-{uuid.uuid4().hex[:8]}",
    }
    if election_priv is not None:
        close_payload["election_signature"] = assinar_eleicao(election_priv, close_payload)
    else:
        close_payload["election_signature"] = base64.b64encode(b"sig_dummy_created_close").decode("utf-8")
    probes.append(
        _probe_desktop(
            "Salto CREATED -> close",
            "/api/election/close/",
            admin_reject_statuses,
            base_url,
            api_pub_desktop,
            close_payload,
            signer=creator_signer,
            machine_pub_pem=pub_pem,
            auth_token=auth_token,
        )
    )

    # 2. Tentar obter votos cifrados ainda CREATED
    probes.append(
        _probe_desktop(
            "Salto CREATED -> tally/votes",
            "/api/election/tally/votes/",
            admin_reject_statuses,
            base_url,
            api_pub_desktop,
            {"msg": "FETCH_VOTES_FOR_TALLY", "keyHandle": snap.key_handle, "nonceClient": f"fsm-m1-tv-{uuid.uuid4().hex[:8]}"},
            signer=creator_signer,
            machine_pub_pem=pub_pem,
            auth_token=auth_token,
        )
    )

    # 3. Tentar apurar eleição ainda CREATED (com chave privada real se disponível)
    priv_pem = (
        election_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        if election_priv is not None
        else _dummy_rsa_private_pem()
    )
    probes.append(
        _probe_desktop(
            "Salto CREATED -> tally",
            "/api/election/tally/",
            admin_reject_statuses,
            base_url,
            api_pub_desktop,
            {
                "msg": "SUBMIT_TALLY",
                "keyHandle": snap.key_handle,
                "tally_hash": hashlib.sha256(b"fsm-m1-tally").hexdigest(),
                "private_key": priv_pem,
                "results": {"Pergunta": {"Opcao": 1}},
                "nonceClient": f"fsm-m1-t-{uuid.uuid4().hex[:8]}",
            },
            signer=creator_signer,
            machine_pub_pem=pub_pem,
            auth_token=auth_token,
        )
    )

    # 4. Endpoints públicos não devem expor rascunho CREATED
    for ep_name, path in (
        ("Exposição pública CREATED (/election/public/<id>/)", f"/api/election/public/{snap.id}/"),
        ("Exposição pública CREATED (/election/track/<id>/)", f"/api/election/track/{snap.id}/"),
        ("Exposição pública CREATED (/public/elections/<id>/)", f"/api/public/elections/{snap.id}/"),
    ):
        pr, _ = _probe_get_status(ep_name, path, (404,), base_url)
        probes.append(pr)

    open_probe, open_body = _probe_get_status(
        "Listagem pública omite rascunho CREATED",
        "/api/election/public/open/",
        (200,),
        base_url,
    )
    if isinstance(open_body, list) and any(isinstance(e, dict) and e.get("id") == snap.id for e in open_body):
        open_probe.passed = False
        open_probe.detail = f"Eleição CREATED #{snap.id} apareceu em /api/election/public/open/"
    probes.append(open_probe)

    # 5. Pacote de auditoria em CREATED deve falhar
    pr_zip, _ = _probe_get_status(
        "Download audit-package em CREATED",
        f"/api/election/public/{snap.id}/audit-package/",
        (400, 404),
        base_url,
    )
    probes.append(pr_zip)

    # 6. Token de votação em CREATED (se fornecido)
    if vote_token:
        v_code, v_body, _ = solicitar_cedula_mobile(base_url, api_pub_mobile, vote_token)
        probes.append(
            AttackProbe(
                name="Votação prematura em CREATED (/vote/request/)",
                endpoint="POST /api/vote/request/",
                http_status=v_code,
                expected_statuses=(400, 403),
                passed=v_code in (400, 403),
                detail=f"HTTP {v_code} (esperado [400, 403])",
                response_preview=_preview(v_body),
            )
        )

    return _build_check_from_probes(
        "M1",
        "Segregação da Fase CREATED (Rascunho)",
        probes,
        "Fase CREATED rejeitou fechamento, apuração e exposição pública",
        extra_notes=extra_notes,
    )


def auditar_fase_started(
    base_url: str,
    snap: ElectionSnapshot,
    api_pub_desktop: rsa.RSAPublicKey,
    creator_signer: MachineSignerBase | None,
    creator_pub_pem: str | None,
    election_priv: rsa.RSAPrivateKey | None,
    auth_token: str | None,
) -> CheckResult:
    """M2: Segregação da fase STARTED (bloqueia apuração prematura e re-início)."""
    probes: list[AttackProbe] = []
    extra_notes: list[str] = []
    pub_pem = creator_pub_pem or snap.creator_machine_public_key
    rogue_signer = EphemeralMachineSigner()
    admin_reject_statuses = (400, 403) if auth_token else (400, 401, 403)
    start_reject_statuses = (400, 403, 404) if auth_token else (400, 401, 403, 404)
    if not auth_token:
        extra_notes.append(
            "Executado sem --auth-token; rotas administrativas rejeitam com HTTP 401 antes da validação de fase. "
            "Passe --auth-token (ou --admin-password + --admin-totp) para validar transições como administrador autenticado."
        )

    # 1. Tentar reiniciar eleição já STARTED
    start_payload: dict[str, Any] = {
        "msg": "START_ELECTION",
        "keyHandle": snap.key_handle,
        "nonceClient2": f"fsm-m2-start-{uuid.uuid4().hex[:8]}",
    }
    if election_priv is not None:
        start_payload["election_signature"] = assinar_eleicao(election_priv, start_payload)
    else:
        start_payload["election_signature"] = base64.b64encode(b"sig_dummy_restart").decode("utf-8")
    probes.append(
        _probe_desktop(
            "Re-início em STARTED (/election/start/)",
            "/api/election/start/",
            start_reject_statuses,
            base_url,
            api_pub_desktop,
            start_payload,
            signer=creator_signer,
            machine_pub_pem=pub_pem,
            auth_token=auth_token,
        )
    )

    # 2. Tentar baixar cédulas cifradas durante STARTED (criadora e intrusa)
    probes.append(
        _probe_desktop(
            "Apuração prematura STARTED -> tally/votes (criadora)",
            "/api/election/tally/votes/",
            admin_reject_statuses,
            base_url,
            api_pub_desktop,
            {"msg": "FETCH_VOTES_FOR_TALLY", "keyHandle": snap.key_handle, "nonceClient": f"fsm-m2-tv1-{uuid.uuid4().hex[:8]}"},
            signer=creator_signer,
            machine_pub_pem=pub_pem,
            auth_token=auth_token,
        )
    )
    probes.append(
        _probe_desktop(
            "Apuração prematura STARTED -> tally/votes (máquina intrusa)",
            "/api/election/tally/votes/",
            admin_reject_statuses,
            base_url,
            api_pub_desktop,
            {"msg": "FETCH_VOTES_FOR_TALLY", "keyHandle": snap.key_handle, "nonceClient": f"fsm-m2-tv2-{uuid.uuid4().hex[:8]}"},
            signer=rogue_signer,
            auth_token=auth_token,
        )
    )

    # 3. Tentar apurar em STARTED (mesmo enviando chave privada real da eleição!)
    priv_pem = (
        election_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        if election_priv is not None
        else _dummy_rsa_private_pem()
    )
    probes.append(
        _probe_desktop(
            "Salto STARTED -> tally (com private_key)" if election_priv else "Salto STARTED -> tally",
            "/api/election/tally/",
            admin_reject_statuses,
            base_url,
            api_pub_desktop,
            {
                "msg": "SUBMIT_TALLY",
                "keyHandle": snap.key_handle,
                "tally_hash": hashlib.sha256(b"fsm-m2-premature-tally").hexdigest(),
                "private_key": priv_pem,
                "results": {"Pergunta": {"Opcao": 1}},
                "nonceClient": f"fsm-m2-t-{uuid.uuid4().hex[:8]}",
            },
            signer=creator_signer,
            machine_pub_pem=pub_pem,
            auth_token=auth_token,
        )
    )

    # 4. Endpoints públicos em STARTED devem omitir private_key, votes e tallies
    for ep_name, path in (
        ("Sigilo público em STARTED (/election/public/<id>/)", f"/api/election/public/{snap.id}/"),
        ("Sigilo público em STARTED (/public/elections/<id>/)", f"/api/public/elections/{snap.id}/"),
    ):
        pr, pub_data = _probe_get_status(ep_name, path, (200,), base_url)
        if pr.passed and isinstance(pub_data, dict):
            leaks = []
            if pub_data.get("status") != "STARTED":
                leaks.append(f"status={pub_data.get('status')!r}")
            if pub_data.get("private_key") is not None:
                leaks.append("private_key exposta")
            if pub_data.get("votes"):
                leaks.append(f"{len(pub_data.get('votes', []))} voto(s) exposto(s)")
            if pub_data.get("tallies"):
                leaks.append("tallies expostos")
            if pub_data.get("tally_results") is not None:
                leaks.append("tally_results exposto")
            if leaks:
                pr.passed = False
                pr.detail = f"Vazamento pré-apuração em STARTED: {', '.join(leaks)}"
        probes.append(pr)

    # 5. Pacote ZIP bloqueado em STARTED
    for ep_name, path in (
        ("Download audit-package em STARTED", f"/api/election/public/{snap.id}/audit-package/"),
        ("Download audit-zip em STARTED", f"/api/election/public/{snap.id}/audit-zip/"),
    ):
        pr_zip, _ = _probe_get_status(ep_name, path, (400,), base_url)
        probes.append(pr_zip)

    return _build_check_from_probes(
        "M2",
        "Segregação da Fase STARTED (Votação Aberta)",
        probes,
        "Fase STARTED bloqueou apuração antecipada, download de cédulas e vazamento de chave",
        extra_notes=extra_notes,
    )


def auditar_fase_closed(
    base_url: str,
    snap: ElectionSnapshot,
    api_pub_desktop: rsa.RSAPublicKey,
    api_pub_mobile: rsa.RSAPublicKey,
    creator_signer: MachineSignerBase | None,
    creator_pub_pem: str | None,
    election_priv: rsa.RSAPrivateKey | None,
    prepared_ballot_before_close: dict[str, Any] | None,
    late_vote_token: str | None,
    auth_token: str | None,
) -> CheckResult:
    """M3: Inviolabilidade pós-fechamento CLOSED (bloqueia reabertura, voto tardio e máquina intrusa)."""
    probes: list[AttackProbe] = []
    extra_notes: list[str] = []
    pub_pem = creator_pub_pem or snap.creator_machine_public_key
    rogue_signer = EphemeralMachineSigner()
    admin_reject_statuses = (400, 403) if auth_token else (400, 401, 403)
    start_reject_statuses = (400, 403, 404) if auth_token else (400, 401, 403, 404)
    rogue_reject_statuses = (403,) if auth_token else (401, 403)
    if not auth_token:
        extra_notes.append(
            "Executado sem --auth-token; rotas administrativas rejeitam com HTTP 401 antes da validação de fase. "
            "Passe --auth-token (ou --admin-password + --admin-totp) para validar transições como administrador autenticado."
        )

    # 1. Retrocesso CLOSED -> start
    start_payload: dict[str, Any] = {
        "msg": "START_ELECTION",
        "keyHandle": snap.key_handle,
        "nonceClient2": f"fsm-m3-start-{uuid.uuid4().hex[:8]}",
    }
    if election_priv is not None:
        start_payload["election_signature"] = assinar_eleicao(election_priv, start_payload)
    else:
        start_payload["election_signature"] = base64.b64encode(b"sig_dummy_reopen").decode("utf-8")
    probes.append(
        _probe_desktop(
            "Retrocesso CLOSED -> start",
            "/api/election/start/",
            start_reject_statuses,
            base_url,
            api_pub_desktop,
            start_payload,
            signer=creator_signer,
            machine_pub_pem=pub_pem,
            auth_token=auth_token,
        )
    )

    # 2. Duplo fechamento CLOSED -> close
    close_payload: dict[str, Any] = {
        "msg": "CLOSE_ELECTION",
        "keyHandle": snap.key_handle,
        "nonceClient3": f"fsm-m3-close-{uuid.uuid4().hex[:8]}",
    }
    if election_priv is not None:
        close_payload["election_signature"] = assinar_eleicao(election_priv, close_payload)
    else:
        close_payload["election_signature"] = base64.b64encode(b"sig_dummy_reclose").decode("utf-8")
    probes.append(
        _probe_desktop(
            "Duplo fechamento CLOSED -> close",
            "/api/election/close/",
            admin_reject_statuses,
            base_url,
            api_pub_desktop,
            close_payload,
            signer=creator_signer,
            machine_pub_pem=pub_pem,
            auth_token=auth_token,
        )
    )

    # 3a. Injeção tardia via /vote/cast/ de cédula obtida antes de fechar
    if prepared_ballot_before_close is not None:
        c_code, c_body = depositar_voto_mobile(base_url, api_pub_mobile, prepared_ballot_before_close)
        probes.append(
            AttackProbe(
                name="Depósito tardio pós-CLOSE (/vote/cast/ com id_voto prévio)",
                endpoint="POST /api/vote/cast/",
                http_status=c_code,
                expected_statuses=(400, 403),
                passed=c_code in (400, 403),
                detail=f"HTTP {c_code} (esperado [400, 403])",
                response_preview=_preview(c_body),
            )
        )

    # 3b. Tentativa de solicitar nova cédula após CLOSE
    if late_vote_token:
        r_code, r_body, _ = solicitar_cedula_mobile(base_url, api_pub_mobile, late_vote_token)
        probes.append(
            AttackProbe(
                name="Solicitação tardia pós-CLOSE (/vote/request/)",
                endpoint="POST /api/vote/request/",
                http_status=r_code,
                expected_statuses=(400, 403),
                passed=r_code in (400, 403),
                detail=f"HTTP {r_code} (esperado [400, 403])",
                response_preview=_preview(r_body),
            )
        )

    # 4. Sigilo pré-apuração na API pública durante CLOSED
    pr_pub, pub_data = _probe_get_status(
        "Sigilo público em CLOSED (/election/public/<id>/)",
        f"/api/election/public/{snap.id}/",
        (200,),
        base_url,
    )
    if pr_pub.passed and isinstance(pub_data, dict):
        leaks = []
        if pub_data.get("status") != "CLOSED":
            leaks.append(f"status={pub_data.get('status')!r}")
        if pub_data.get("private_key") is not None:
            leaks.append("private_key exposta antes de TALLIED")
        if pub_data.get("votes"):
            leaks.append("votes expostos antes de TALLIED")
        if pub_data.get("tallies"):
            leaks.append("tallies expostos antes de TALLIED")
        if pub_data.get("tally_results") is not None:
            leaks.append("tally_results exposto antes de TALLIED")
        if leaks:
            pr_pub.passed = False
            pr_pub.detail = f"Vazamento em CLOSED: {', '.join(leaks)}"
    probes.append(pr_pub)

    pr_zip, _ = _probe_get_status(
        "Download audit-package bloqueado em CLOSED",
        f"/api/election/public/{snap.id}/audit-package/",
        (400,),
        base_url,
    )
    probes.append(pr_zip)

    # 5. Isolamento em CLOSED: máquina intrusa não pode baixar votos nem submeter apuração
    if snap.creator_machine_public_key:
        probes.append(
            _probe_desktop(
                "Isolamento em CLOSED: máquina intrusa -> tally/votes",
                "/api/election/tally/votes/",
                rogue_reject_statuses,
                base_url,
                api_pub_desktop,
                {"msg": "FETCH_VOTES_FOR_TALLY", "keyHandle": snap.key_handle, "nonceClient": f"fsm-m3-rogue-tv-{uuid.uuid4().hex[:8]}"},
                signer=rogue_signer,
                auth_token=auth_token,
            )
        )
        priv_pem = (
            election_priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode("utf-8")
            if election_priv is not None
            else _dummy_rsa_private_pem()
        )
        probes.append(
            _probe_desktop(
                "Isolamento em CLOSED: máquina intrusa -> tally",
                "/api/election/tally/",
                rogue_reject_statuses,
                base_url,
                api_pub_desktop,
                {
                    "msg": "SUBMIT_TALLY",
                    "keyHandle": snap.key_handle,
                    "tally_hash": hashlib.sha256(b"fsm-m3-rogue-tally").hexdigest(),
                    "private_key": priv_pem,
                    "results": {"Pergunta": {"Opcao": 1}},
                    "nonceClient": f"fsm-m3-rogue-t-{uuid.uuid4().hex[:8]}",
                },
                signer=rogue_signer,
                auth_token=auth_token,
            )
        )

    return _build_check_from_probes(
        "M3",
        "Inviolabilidade Pós-Encerramento (CLOSED)",
        probes,
        "Fase CLOSED impediu reabertura, votos tardios, vazamento público e acesso de máquina intrusa",
        extra_notes=extra_notes,
    )


def auditar_fase_tallied(
    base_url: str,
    snap: ElectionSnapshot,
    api_pub_desktop: rsa.RSAPublicKey,
    api_pub_mobile: rsa.RSAPublicKey,
    creator_signer: MachineSignerBase | None,
    creator_pub_pem: str | None,
    election_priv: rsa.RSAPrivateKey | None,
    prepared_ballot_before_close: dict[str, Any] | None,
    late_vote_token: str | None,
    auth_token: str | None,
) -> CheckResult:
    """M4: Terminalidade da fase TALLIED (publicação íntegra + rejeição de mutações/sobrescrita)."""
    probes: list[AttackProbe] = []
    extra_notes: list[str] = []
    pub_pem = creator_pub_pem or snap.creator_machine_public_key
    admin_reject_statuses = (400, 403) if auth_token else (400, 401, 403)
    start_reject_statuses = (400, 403, 404) if auth_token else (400, 401, 403, 404)
    if not auth_token:
        extra_notes.append(
            "Executado sem --auth-token; rotas administrativas rejeitam com HTTP 401 antes da validação de fase. "
            "Passe --auth-token (ou --admin-password + --admin-totp) para validar transições como administrador autenticado."
        )

    # 1. Conferir publicação pós-TALLIED e integridade do pacote ZIP
    pr_pub, pub_data = _probe_get_status(
        "Publicação pós-TALLIED (/election/public/<id>/)",
        f"/api/election/public/{snap.id}/",
        (200,),
        base_url,
    )
    if pr_pub.passed and isinstance(pub_data, dict):
        missing = []
        if pub_data.get("status") != "TALLIED":
            missing.append(f"status={pub_data.get('status')!r}")
        if not pub_data.get("private_key"):
            missing.append("private_key ausente")
        if not pub_data.get("tallies"):
            missing.append("tallies vazio")
        if missing:
            pr_pub.passed = False
            pr_pub.detail = f"Publicação TALLIED incompleta: {', '.join(missing)}"
    probes.append(pr_pub)

    resp_zip = requests.get(f"{base_url.rstrip('/')}/api/election/public/{snap.id}/audit-package/", timeout=15)
    zip_ok = False
    zip_detail = f"HTTP {resp_zip.status_code}"
    if resp_zip.status_code == 200:
        try:
            with zipfile.ZipFile(io.BytesIO(resp_zip.content), "r") as zf:
                names = set(zf.namelist())
            required = {"chave_privada.pem", "votos_criptografados.json", "dados_eleicao.json", "LEIAME.txt"}
            missing_files = sorted(required - names)
            if not missing_files:
                zip_ok = True
                zip_detail = f"HTTP 200 (ZIP válido com {sorted(names)})"
            else:
                zip_detail = f"ZIP incompleto; faltam {missing_files}"
        except zipfile.BadZipFile as exc:
            zip_detail = f"ZIP corrompido: {exc}"
    probes.append(
        AttackProbe(
            name="Pacote ZIP de auditoria em TALLIED",
            endpoint=f"GET /api/election/public/{snap.id}/audit-package/",
            http_status=resp_zip.status_code,
            expected_statuses=(200,),
            passed=zip_ok,
            detail=zip_detail,
            response_preview=f"bytes={len(resp_zip.content)}",
        )
    )

    # 2. Retrocesso TALLIED -> start
    start_payload: dict[str, Any] = {
        "msg": "START_ELECTION",
        "keyHandle": snap.key_handle,
        "nonceClient2": f"fsm-m4-start-{uuid.uuid4().hex[:8]}",
    }
    if election_priv is not None:
        start_payload["election_signature"] = assinar_eleicao(election_priv, start_payload)
    else:
        start_payload["election_signature"] = base64.b64encode(b"sig_dummy_tallied_start").decode("utf-8")
    probes.append(
        _probe_desktop(
            "Retrocesso TALLIED -> start",
            "/api/election/start/",
            start_reject_statuses,
            base_url,
            api_pub_desktop,
            start_payload,
            signer=creator_signer,
            machine_pub_pem=pub_pem,
            auth_token=auth_token,
        )
    )

    # 3. Retrocesso TALLIED -> close
    close_payload: dict[str, Any] = {
        "msg": "CLOSE_ELECTION",
        "keyHandle": snap.key_handle,
        "nonceClient3": f"fsm-m4-close-{uuid.uuid4().hex[:8]}",
    }
    if election_priv is not None:
        close_payload["election_signature"] = assinar_eleicao(election_priv, close_payload)
    else:
        close_payload["election_signature"] = base64.b64encode(b"sig_dummy_tallied_close").decode("utf-8")
    probes.append(
        _probe_desktop(
            "Retrocesso TALLIED -> close",
            "/api/election/close/",
            admin_reject_statuses,
            base_url,
            api_pub_desktop,
            close_payload,
            signer=creator_signer,
            machine_pub_pem=pub_pem,
            auth_token=auth_token,
        )
    )

    # 4. Sobrescrita de Tally em TALLIED -> tally
    priv_pem = (
        election_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        if election_priv is not None
        else (pub_data.get("private_key") if isinstance(pub_data, dict) and pub_data.get("private_key") else _dummy_rsa_private_pem())
    )
    probes.append(
        _probe_desktop(
            "Sobrescrita de apuração TALLIED -> tally",
            "/api/election/tally/",
            admin_reject_statuses,
            base_url,
            api_pub_desktop,
            {
                "msg": "SUBMIT_TALLY",
                "keyHandle": snap.key_handle,
                "tally_hash": hashlib.sha256(b"fsm-m4-overwrite-tally").hexdigest(),
                "private_key": priv_pem,
                "results": {"Pergunta": {"Opcao": 999}},
                "nonceClient": f"fsm-m4-t-{uuid.uuid4().hex[:8]}",
            },
            signer=creator_signer,
            machine_pub_pem=pub_pem,
            auth_token=auth_token,
        )
    )

    # 5. Injeção de voto tardio pós-TALLIED
    if prepared_ballot_before_close is not None:
        c_code, c_body = depositar_voto_mobile(base_url, api_pub_mobile, prepared_ballot_before_close)
        probes.append(
            AttackProbe(
                name="Depósito tardio pós-TALLIED (/vote/cast/)",
                endpoint="POST /api/vote/cast/",
                http_status=c_code,
                expected_statuses=(400, 403),
                passed=c_code in (400, 403),
                detail=f"HTTP {c_code} (esperado [400, 403])",
                response_preview=_preview(c_body),
            )
        )
    if late_vote_token:
        r_code, r_body, _ = solicitar_cedula_mobile(base_url, api_pub_mobile, late_vote_token)
        probes.append(
            AttackProbe(
                name="Solicitação tardia pós-TALLIED (/vote/request/)",
                endpoint="POST /api/vote/request/",
                http_status=r_code,
                expected_statuses=(400, 403),
                passed=r_code in (400, 403),
                detail=f"HTTP {r_code} (esperado [400, 403])",
                response_preview=_preview(r_body),
            )
        )

    return _build_check_from_probes(
        "M4",
        "Terminalidade da Fase TALLIED (Eleição Apurada)",
        probes,
        "Fase TALLIED publicou pacote completo e bloqueou retrocessos, sobrescrita e novos votos",
        extra_notes=extra_notes,
    )


def auditar_criptografia_e_controle_acesso(
    base_url: str,
    snap: ElectionSnapshot,
    api_pub_desktop: rsa.RSAPublicKey,
    creator_signer: MachineSignerBase | None,
    creator_pub_pem: str | None,
    election_priv: rsa.RSAPrivateKey | None,
    non_creator_token: str | None,
    strict_auth: bool,
    auth_token: str | None = None,
    run_plaintext: bool = True,
    run_access_control: bool = True,
    probe_available_auth: bool = True,
) -> CheckResult:
    """M5: Bypass de transporte TPM, assinaturas inválidas, chave falsa e controle de acesso."""
    probes: list[AttackProbe] = []
    extra_notes: list[str] = []
    has_alert = False
    pub_pem = creator_pub_pem or snap.creator_machine_public_key
    rogue_signer = EphemeralMachineSigner()

    # 1. Bypass de transporte TPM (JSON em texto plano)
    if run_plaintext:
        for ep_name, path, pl in (
            ("Bypass plaintext -> start", "/api/election/start/", {"msg": "START_ELECTION", "keyHandle": snap.key_handle, "nonceClient2": "plain-1"}),
            ("Bypass plaintext -> close", "/api/election/close/", {"msg": "CLOSE_ELECTION", "keyHandle": snap.key_handle, "nonceClient3": "plain-2"}),
            ("Bypass plaintext -> tally/votes", "/api/election/tally/votes/", {"msg": "FETCH_VOTES_FOR_TALLY", "keyHandle": snap.key_handle, "nonceClient": "plain-3"}),
            ("Bypass plaintext -> tally", "/api/election/tally/", {"msg": "SUBMIT_TALLY", "keyHandle": snap.key_handle, "nonceClient": "plain-4"}),
        ):
            probes.append(
                _probe_desktop(
                    ep_name,
                    path,
                    (400,),
                    base_url,
                    api_pub_desktop,
                    pl,
                    machine_pub_pem=pub_pem,
                    auth_token=auth_token,
                    plaintext=True,
                )
            )

    # 2. Assinaturas da eleição ausentes/adulteradas e isolamento de hardware específico da fase
    if snap.status == "CREATED":
        probes.append(
            _probe_desktop(
                "START sem election_signature",
                "/api/election/start/",
                (400, 401),
                base_url,
                api_pub_desktop,
                {"msg": "START_ELECTION", "keyHandle": snap.key_handle, "nonceClient2": f"fsm-m5-nosig-{uuid.uuid4().hex[:8]}"},
                signer=creator_signer,
                machine_pub_pem=pub_pem,
                auth_token=auth_token,
            )
        )
        probes.append(
            _probe_desktop(
                "START com election_signature adulterada",
                "/api/election/start/",
                (403,) if auth_token else (401, 403),
                base_url,
                api_pub_desktop,
                {
                    "msg": "START_ELECTION",
                    "keyHandle": snap.key_handle,
                    "nonceClient2": f"fsm-m5-badsig-{uuid.uuid4().hex[:8]}",
                    "election_signature": base64.b64encode(b"assinatura_eleicao_falsa_12345").decode("utf-8"),
                },
                signer=creator_signer,
                machine_pub_pem=pub_pem,
                auth_token=auth_token,
            )
        )

    if snap.status == "STARTED":
        probes.append(
            _probe_desktop(
                "CLOSE sem election_signature",
                "/api/election/close/",
                (400, 401),
                base_url,
                api_pub_desktop,
                {"msg": "CLOSE_ELECTION", "keyHandle": snap.key_handle, "nonceClient3": f"fsm-m5-cnosig-{uuid.uuid4().hex[:8]}"},
                signer=creator_signer,
                machine_pub_pem=pub_pem,
                auth_token=auth_token,
            )
        )
        probes.append(
            _probe_desktop(
                "CLOSE com election_signature adulterada",
                "/api/election/close/",
                (403,) if auth_token else (401, 403),
                base_url,
                api_pub_desktop,
                {
                    "msg": "CLOSE_ELECTION",
                    "keyHandle": snap.key_handle,
                    "nonceClient3": f"fsm-m5-cbadsig-{uuid.uuid4().hex[:8]}",
                    "election_signature": base64.b64encode(b"assinatura_close_falsa_12345").decode("utf-8"),
                },
                signer=creator_signer,
                machine_pub_pem=pub_pem,
                auth_token=auth_token,
            )
        )
        if snap.creator_machine_public_key:
            rogue_close_payload: dict[str, Any] = {
                "msg": "CLOSE_ELECTION",
                "keyHandle": snap.key_handle,
                "nonceClient3": f"fsm-m5-crogue-{uuid.uuid4().hex[:8]}",
            }
            if election_priv is not None:
                rogue_close_payload["election_signature"] = assinar_eleicao(election_priv, rogue_close_payload)
            else:
                rogue_close_payload["election_signature"] = base64.b64encode(b"sig_dummy_rogue_close").decode("utf-8")
            probes.append(
                _probe_desktop(
                    "CLOSE por máquina intrusa (mesmo com election_signature)" if election_priv else "CLOSE por máquina intrusa",
                    "/api/election/close/",
                    (403,) if auth_token else (401, 403),
                    base_url,
                    api_pub_desktop,
                    rogue_close_payload,
                    signer=rogue_signer,
                    auth_token=auth_token,
                )
            )

    # 3. Integridade criptográfica da apuração em CLOSED
    if snap.status == "CLOSED":
        probes.append(
            _probe_desktop(
                "TALLY com chave privada incompatível (par RSA errado)",
                "/api/election/tally/",
                (400,) if auth_token else (400, 401),
                base_url,
                api_pub_desktop,
                {
                    "msg": "SUBMIT_TALLY",
                    "keyHandle": snap.key_handle,
                    "tally_hash": hashlib.sha256(b"fsm-m5-wrong-key").hexdigest(),
                    "private_key": _dummy_rsa_private_pem(),
                    "results": {"Pergunta": {"Opcao": 1}},
                    "nonceClient": f"fsm-m5-wkey-{uuid.uuid4().hex[:8]}",
                },
                signer=creator_signer,
                machine_pub_pem=pub_pem,
                auth_token=auth_token,
            )
        )
        if election_priv is not None and snap.votes_count > 0:
            real_priv_pem = election_priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode("utf-8")
            probes.append(
                _probe_desktop(
                    "TALLY com contagem zerada havendo cédulas na urna",
                    "/api/election/tally/",
                    (400,) if auth_token else (400, 401),
                    base_url,
                    api_pub_desktop,
                    {
                        "msg": "SUBMIT_TALLY",
                        "keyHandle": snap.key_handle,
                        "tally_hash": hashlib.sha256(b"fsm-m5-zeroed").hexdigest(),
                        "private_key": real_priv_pem,
                        "results": {"summary": {}},
                        "nonceClient": f"fsm-m5-zero-{uuid.uuid4().hex[:8]}",
                    },
                    signer=creator_signer,
                    machine_pub_pem=pub_pem,
                    auth_token=auth_token,
                )
            )

    # 4. Controle de acesso e verificação de assinatura do envelope em rotas NÃO-MUTÁVEIS
    if run_access_control and pub_pem:
        badsig_expected = (403,) if auth_token else (401, 403)
        auth_label = "com Authorization" if auth_token else "sem Authorization"

        # 4a. Assinatura RSA-PSS do envelope propositalmente adulterada em /election/available/
        if probe_available_auth:
            nonce_av = f"fsm-m5-avail-badsig-{uuid.uuid4().hex[:8]}"
            code_av, body_av = _post_desktop(
                base_url,
                "/api/election/available/",
                api_pub_desktop,
                {"msg": "FETCH_AVAILABLE", "nonceClient1": nonce_av, "status": snap.status},
                machine_pub_pem=pub_pem,
                tamper_signature=True,
                auth_token=auth_token,
            )
            probes.append(
                AttackProbe(
                    name=f"Envelope /election/available/ com signature adulterada ({auth_label})",
                    endpoint="POST /api/election/available/",
                    http_status=code_av,
                    expected_statuses=badsig_expected,
                    passed=code_av in badsig_expected,
                    detail=(
                        f"HTTP {code_av} — SEDecryptMiddleware aceitou assinatura adulterada"
                        if code_av == 200
                        else f"HTTP {code_av} (esperado {list(badsig_expected)})"
                    ),
                    response_preview=_preview(body_av),
                )
            )

        # 4b. Em CLOSED, testar /election/tally/votes/ com signature adulterada
        if snap.status == "CLOSED":
            code_tv, body_tv = _post_desktop(
                base_url,
                "/api/election/tally/votes/",
                api_pub_desktop,
                {"msg": "FETCH_VOTES_FOR_TALLY", "keyHandle": snap.key_handle, "nonceClient": f"fsm-m5-tv-badsig-{uuid.uuid4().hex[:8]}"},
                machine_pub_pem=pub_pem,
                tamper_signature=True,
                auth_token=auth_token,
            )
            probes.append(
                AttackProbe(
                    name=f"Envelope /election/tally/votes/ com signature adulterada ({auth_label})",
                    endpoint="POST /api/election/tally/votes/",
                    http_status=code_tv,
                    expected_statuses=badsig_expected,
                    passed=code_tv in badsig_expected,
                    detail=(
                        f"HTTP {code_tv} — cédulas cifradas entregues sem assinatura válida"
                        if code_tv == 200
                        else f"HTTP {code_tv} (esperado {list(badsig_expected)})"
                    ),
                    response_preview=_preview(body_tv),
                )
            )

        # 4c. Requisição com assinatura TPM válida SEM cabeçalho Authorization
        def _check_noauth(ep_label: str, path: str, pl: dict[str, Any]) -> None:
            nonlocal has_alert
            code_na, body_na = _post_desktop(
                base_url,
                path,
                api_pub_desktop,
                pl,
                signer=creator_signer,
                machine_pub_pem=pub_pem,
            )
            if code_na in (401, 403):
                probes.append(
                    AttackProbe(
                        name=ep_label,
                        endpoint=f"POST {path}",
                        http_status=code_na,
                        expected_statuses=(401, 403),
                        passed=True,
                        detail=f"HTTP {code_na} (esperado [401, 403])",
                        response_preview=_preview(body_na),
                    )
                )
            elif strict_auth:
                probes.append(
                    AttackProbe(
                        name=f"{ep_label} (--strict-auth)",
                        endpoint=f"POST {path}",
                        http_status=code_na,
                        expected_statuses=(401, 403),
                        passed=False,
                        detail=f"HTTP {code_na} (strict-auth exige 401/403)",
                        response_preview=_preview(body_na),
                    )
                )
            else:
                has_alert = True
                extra_notes.append(
                    f"[ALERTA] POST {path} aceitou requisição sem cabeçalho Authorization (HTTP {code_na})."
                )

        if creator_signer is not None:
            if probe_available_auth:
                _check_noauth(
                    "Requisição /election/available/ sem header Authorization",
                    "/api/election/available/",
                    {"msg": "FETCH_AVAILABLE", "nonceClient1": f"fsm-m5-noauth-{uuid.uuid4().hex[:8]}", "status": snap.status},
                )
            if snap.status == "CLOSED":
                _check_noauth(
                    "Requisição /election/tally/votes/ sem header Authorization",
                    "/api/election/tally/votes/",
                    {"msg": "FETCH_VOTES_FOR_TALLY", "keyHandle": snap.key_handle, "nonceClient": f"fsm-m5-tv-noauth-{uuid.uuid4().hex[:8]}"},
                )

        # 4d. Usuário autenticado diferente do criador (--non-creator-token)
        if non_creator_token and snap.status in ("STARTED", "CLOSED"):
            target_ep = "/api/election/tally/votes/" if snap.status == "CLOSED" else "/api/election/close/"
            nc_payload: dict[str, Any] = (
                {"msg": "FETCH_VOTES_FOR_TALLY", "keyHandle": snap.key_handle, "nonceClient": f"fsm-m5-nc-{uuid.uuid4().hex[:8]}"}
                if snap.status == "CLOSED"
                else {
                    "msg": "CLOSE_ELECTION",
                    "keyHandle": snap.key_handle,
                    "nonceClient3": f"fsm-m5-nc-{uuid.uuid4().hex[:8]}",
                    "election_signature": base64.b64encode(b"sig_non_creator").decode("utf-8"),
                }
            )
            probes.append(
                _probe_desktop(
                    "Usuário não-criador (--non-creator-token)",
                    target_ep,
                    (403,),
                    base_url,
                    api_pub_desktop,
                    nc_payload,
                    signer=rogue_signer,
                    auth_token=non_creator_token,
                )
            )

    return _build_check_from_probes(
        "M5",
        "Envelopes TPM, Assinaturas Criptográficas e Controle de Acesso",
        probes,
        "Transporte híbrido, assinaturas e controle de acesso validados",
        extra_notes=extra_notes,
        has_alert=has_alert,
    )


def auditar_invariancia_banco(
    invariance_records: list[tuple[str, ElectionSnapshot, ElectionSnapshot, list[str]]],
    lifecycle_transitions: list[str] | None = None,
) -> CheckResult:
    """M6: Consolida verificações de invariância do banco antes/depois de cada bateria de ataque."""
    all_diffs: list[str] = []
    details: list[str] = []

    if lifecycle_transitions is not None:
        details.append(f"Transições legítimas observadas: {' -> '.join(lifecycle_transitions)}")
        if lifecycle_transitions != list(VALID_STATES):
            all_diffs.append(
                f"Sequência de ciclo de vida inesperada: {lifecycle_transitions} (esperado {list(VALID_STATES)})"
            )

    for label, before, after, diffs in invariance_records:
        if diffs:
            all_diffs.extend(diffs)
            details.append(f"[VIOLAÇÃO] {label}: {'; '.join(diffs)}")
        else:
            details.append(
                f"[OK] {label}: status={after.status}, votes={after.votes_count}, "
                f"tallies={after.tally_count}, private_key={after.private_key_present}"
            )

    if all_diffs:
        return CheckResult(
            code="M6",
            title="Invariância do Estado Persistido no Banco de Dados",
            status="FALHOU",
            summary=f"{len(all_diffs)} violação(ões) de invariância detectada(s) no banco.",
            details=all_diffs + details,
        )

    return CheckResult(
        code="M6",
        title="Invariância do Estado Persistido no Banco de Dados",
        status="PASSOU",
        summary=f"Estado persistido permaneceu 100% inalterado nas {len(invariance_records)} bateria(s) de ataque.",
        details=details,
    )


# ==============================================================================
# Modos de Execução (--dry-run, --list, --election-id, --full-lifecycle)
# ==============================================================================
def listar_eleicoes_resumo(db: DBAdapter) -> None:
    if not db.table_exists("Domain_election"):
        print("Tabela Domain_election não encontrada.")
        return
    rows = db.query_all(
        """
        SELECT e.id, e.title, e.status, e.key_handle,
               (SELECT COUNT(*) FROM "Domain_electoralcollege" ec WHERE ec.election_id = e.id AND ec.has_voted = %s) AS voted_count,
               (SELECT COUNT(*) FROM "Domain_vote" v WHERE v.election_id = e.id) AS votes_count,
               (SELECT COUNT(*) FROM "Domain_tally" t WHERE t.election_id = e.id) AS tally_count
        FROM "Domain_election" e
        ORDER BY e.id ASC
        """,
        (True,),
    )
    if not rows:
        print("Nenhuma eleição cadastrada no banco.")
        return
    print("\nEleições disponíveis no banco:")
    print(f"  {'ID':>4}  {'Status':<8}  {'Votantes':>8}  {'Urna':>6}  {'Tallies':>7}  {'KeyHandle':<32}  Título")
    print("  " + "-" * 96)
    for r in rows:
        print(
            f"  {r['id']:>4}  {r['status']:<8}  {r['voted_count']:>8}  {r['votes_count']:>6}  "
            f"{r['tally_count']:>7}  {str(r['key_handle'])[:32]:<32}  {r['title']}"
        )


def executar_dry_run(args: argparse.Namespace) -> int:
    """Valida localmente chaves do servidor, signer Desktop (TPM/.enc) e assinaturas."""
    api_pub_1 = carregar_chave_servidor("VotaAI_SecureKey_1", args.se_keys)
    api_pub_2 = carregar_chave_servidor("VotaAI_SecureKey_2", args.se_keys)
    signer = DesktopMachineSigner(args.client_key, args.client_key.parent / ".client_keys")

    sample_payload = {"msg": "DRY_RUN_FSM", "nonceClient1": "dry-nonce-1234", "machine_public_key": signer.public_pem}
    sig = assinar_payload_canonico(signer, sample_payload)
    signed_payload = {**sample_payload, "signature": sig}
    env_desktop = cifrar_envelope(api_pub_1, signed_payload)
    env_mobile = cifrar_envelope(api_pub_2, {"token": "dry-token", "nonce": "dry-mobile"})

    canonical_bytes = json.dumps(sample_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    sig_ok = verificar_assinatura_rsa(_parse_rsa_public_key(signer.public_pem), canonical_bytes, sig)

    election_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    el_sig = assinar_eleicao(election_priv, {"msg": "START_ELECTION", "keyHandle": "dry_handle", "nonceClient2": "n2"})
    el_bytes = json.dumps(
        {"msg": "START_ELECTION", "keyHandle": "dry_handle", "nonceClient2": "n2"},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    el_sig_ok = verificar_assinatura_rsa(election_priv.public_key(), el_bytes, el_sig)

    print("[DRY-RUN] Validação criptográfica concluída com sucesso:")
    print(f"  - VotaAI_SecureKey_1 (Desktop): RSA {api_pub_1.key_size} bits | envelope={len(json.dumps(env_desktop))} bytes")
    print(f"  - VotaAI_SecureKey_2 (Mobile) : RSA {api_pub_2.key_size} bits | envelope={len(json.dumps(env_mobile))} bytes")
    print(f"  - Signer Desktop              : {signer.backend_label} | assinatura verificada={sig_ok}")
    print(f"  - Assinatura de eleição       : RSA-2048 verificada={el_sig_ok}")
    return 0 if (sig_ok and el_sig_ok) else 1


def _combine_m5_results(results: list[CheckResult]) -> CheckResult:
    """Agrupa execuções de M5 ao longo das fases do --full-lifecycle sem perder falhas/alertas."""
    probes: list[AttackProbe] = []
    details: list[str] = []
    has_fail = False
    has_alert = False
    for r in results:
        probes.extend(r.probes)
        details.extend(r.details)
        if r.status == "FALHOU":
            has_fail = True
        elif r.status == "ALERTA":
            has_alert = True

    failed = [p for p in probes if not p.passed]
    if has_fail or failed:
        return CheckResult(
            code="M5",
            title="Envelopes TPM, Assinaturas Criptográficas e Controle de Acesso",
            status="FALHOU",
            summary=f"{len(failed)}/{len(probes)} verificação(ões) falharam ao longo do ciclo.",
            details=details,
            probes=probes,
        )
    if has_alert:
        return CheckResult(
            code="M5",
            title="Envelopes TPM, Assinaturas Criptográficas e Controle de Acesso",
            status="ALERTA",
            summary=f"{len(probes)} verificação(ões) conformes, com alerta(s) de autorização.",
            details=details,
            probes=probes,
        )
    return CheckResult(
        code="M5",
        title="Envelopes TPM, Assinaturas Criptográficas e Controle de Acesso",
        status="PASSOU",
        summary=f"Transporte híbrido, assinaturas e controle de acesso validados ({len(probes)}/{len(probes)}).",
        details=details,
        probes=probes,
    )


def executar_eleicao_existente(args: argparse.Namespace, db: DBAdapter) -> tuple[list[CheckResult], dict[str, Any]]:
    """Audita de forma não-destrutiva uma eleição existente identificada por --election-id."""
    api_pub_1 = carregar_chave_servidor("VotaAI_SecureKey_1", args.se_keys)
    api_pub_2 = carregar_chave_servidor("VotaAI_SecureKey_2", args.se_keys)
    try:
        desktop_signer: MachineSignerBase | None = DesktopMachineSigner(
            args.client_key, args.client_key.parent / ".client_keys"
        )
    except Exception:
        desktop_signer = None

    snap_initial = capturar_snapshot_eleicao(db, args.election_id)
    matching_signer = (
        desktop_signer
        if (
            desktop_signer is not None
            and snap_initial.creator_machine_public_key
            and to_pem_public_key(desktop_signer.public_pem) == snap_initial.creator_machine_public_key
        )
        else None
    )

    auth_token = args.auth_token
    if not auth_token and matching_signer is not None and args.admin_password and args.admin_totp:
        auth_token = autenticar_admin_desktop(
            args.base_url,
            api_pub_1,
            matching_signer,
            db,
            admin_email=args.admin_email,
            admin_password=args.admin_password,
            admin_totp=args.admin_totp,
            device_id=args.device_id,
        )

    invariance_records: list[tuple[str, ElectionSnapshot, ElectionSnapshot, list[str]]] = []

    def _run_phase_with_invariance(label: str, fn: Any) -> CheckResult:
        before = capturar_snapshot_eleicao(db, args.election_id)
        res = fn(before)
        after = capturar_snapshot_eleicao(db, args.election_id)
        diffs = verificar_invariancia(before, after, label)
        invariance_records.append((label, before, after, diffs))
        return res

    checks_by_code: dict[str, CheckResult] = {}

    if snap_initial.status == "CREATED":
        checks_by_code["M1"] = _run_phase_with_invariance(
            "CREATED",
            lambda s: auditar_fase_created(
                args.base_url, s, api_pub_1, api_pub_2, matching_signer, snap_initial.creator_machine_public_key, None, args.vote_token, auth_token
            ),
        )
    else:
        checks_by_code["M1"] = CheckResult(
            code="M1",
            title="Segregação da Fase CREATED (Rascunho)",
            status="N/A",
            summary=f"Eleição #{snap_initial.id} encontra-se em status '{snap_initial.status}'; use --full-lifecycle para testar CREATED.",
        )

    if snap_initial.status == "STARTED":
        checks_by_code["M2"] = _run_phase_with_invariance(
            "STARTED",
            lambda s: auditar_fase_started(
                args.base_url, s, api_pub_1, matching_signer, snap_initial.creator_machine_public_key, None, auth_token
            ),
        )
    else:
        checks_by_code["M2"] = CheckResult(
            code="M2",
            title="Segregação da Fase STARTED (Votação Aberta)",
            status="N/A",
            summary=f"Eleição #{snap_initial.id} encontra-se em status '{snap_initial.status}'; use --full-lifecycle para testar STARTED.",
        )

    if snap_initial.status == "CLOSED":
        checks_by_code["M3"] = _run_phase_with_invariance(
            "CLOSED",
            lambda s: auditar_fase_closed(
                args.base_url, s, api_pub_1, api_pub_2, matching_signer, snap_initial.creator_machine_public_key, None, None, args.vote_token, auth_token
            ),
        )
    else:
        checks_by_code["M3"] = CheckResult(
            code="M3",
            title="Inviolabilidade Pós-Encerramento (CLOSED)",
            status="N/A",
            summary=f"Eleição #{snap_initial.id} encontra-se em status '{snap_initial.status}'; use --full-lifecycle para testar CLOSED.",
        )

    if snap_initial.status == "TALLIED":
        checks_by_code["M4"] = _run_phase_with_invariance(
            "TALLIED",
            lambda s: auditar_fase_tallied(
                args.base_url, s, api_pub_1, api_pub_2, matching_signer, snap_initial.creator_machine_public_key, None, None, args.vote_token, auth_token
            ),
        )
    else:
        checks_by_code["M4"] = CheckResult(
            code="M4",
            title="Terminalidade da Fase TALLIED (Eleição Apurada)",
            status="N/A",
            summary=f"Eleição #{snap_initial.id} encontra-se em status '{snap_initial.status}'; use --full-lifecycle para testar TALLIED.",
        )

    checks_by_code["M5"] = _run_phase_with_invariance(
        f"M5 ({snap_initial.status})",
        lambda s: auditar_criptografia_e_controle_acesso(
            args.base_url,
            s,
            api_pub_1,
            matching_signer,
            snap_initial.creator_machine_public_key,
            None,
            args.non_creator_token,
            args.strict_auth,
            auth_token=auth_token,
            probe_available_auth=True,
        ),
    )
    checks_by_code["M6"] = auditar_invariancia_banco(invariance_records)

    meta = {
        "mode": "election-id",
        "election_id": snap_initial.id,
        "title": snap_initial.title,
        "status": snap_initial.status,
        "signer": desktop_signer.backend_label if desktop_signer else "Somente chave pública do banco",
    }
    return [checks_by_code[k] for k in ("M1", "M2", "M3", "M4", "M5", "M6")], meta


def executar_ciclo_completo(args: argparse.Namespace, db: DBAdapter) -> tuple[list[CheckResult], dict[str, Any]]:
    """Cria eleição efêmera de teste e audita todas as transições CREATED -> STARTED -> CLOSED -> TALLIED."""
    api_pub_1 = carregar_chave_servidor("VotaAI_SecureKey_1", args.se_keys)
    api_pub_2 = carregar_chave_servidor("VotaAI_SecureKey_2", args.se_keys)
    signer = DesktopMachineSigner(args.client_key, args.client_key.parent / ".client_keys")

    creator_user = encontrar_usuario_desktop(db, signer.public_pem)
    if not creator_user:
        raise RuntimeError(
            "Nenhum usuário em Domain_user corresponde à chave pública em client_key.json. "
            "Cadastre/vincule o administrador Desktop antes de executar --full-lifecycle."
        )

    auth_token = args.auth_token
    if not auth_token:
        if args.admin_password and args.admin_totp:
            print(f"[FSM] Autenticando administrador ({args.admin_email or creator_user.get('email')})...")
            auth_token = autenticar_admin_desktop(
                args.base_url,
                api_pub_1,
                signer,
                db,
                admin_email=args.admin_email,
                admin_password=args.admin_password,
                admin_totp=args.admin_totp,
                device_id=args.device_id,
            )
        else:
            raise RuntimeError(
                "O modo --full-lifecycle requer autenticação administrativa. "
                "Informe --auth-token <TOKEN_KNOX> ou --admin-password <SENHA> --admin-totp <CODIGO_6_DIGITOS>."
            )

    election_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    election_pub_pem = (
        election_priv.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    election_priv_pem = election_priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    uid = uuid.uuid4().hex[:12]
    key_handle = f"votaai_fsm_test_{uid}"
    title = f"[TESTE-FSM] Maquina de Estados {datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}-{uid[:6]}"
    voters_emails = [
        f"eleitor1.fsm.{uid}@votaai.test",
        f"eleitor2.fsm.{uid}@votaai.test",
        f"eleitor3.fsm.{uid}@votaai.test",
    ]
    create_payload = {
        "title": title,
        "ballot": [
            {
                "question": "Aprova o protocolo de estados?",
                "order": 1,
                "options": [{"label": "Sim"}, {"label": "Não"}],
            }
        ],
        "electoral_college": [
            {"email": voters_emails[0], "full_name": "Eleitor FSM Um"},
            {"email": voters_emails[1], "full_name": "Eleitor FSM Dois"},
            {"email": voters_emails[2], "full_name": "Eleitor FSM Tres"},
        ],
        "public_key": election_pub_pem,
        "key_handle": key_handle,
    }

    print(f"[FSM] Criando eleição de teste '{title}' (handle={key_handle})...")
    code_cr, body_cr = _post_desktop(
        args.base_url,
        "/api/election/create/",
        api_pub_1,
        create_payload,
        signer=signer,
        auth_token=auth_token,
    )
    if code_cr != 200 or not isinstance(body_cr, dict) or "id" not in body_cr:
        raise RuntimeError(f"Falha ao criar eleição de teste (HTTP {code_cr}): {body_cr}")

    election_id = int(body_cr["id"])
    server_sig_data = f"{election_id}:{body_cr.get('questions_count')}:{body_cr.get('options_count')}".encode("utf-8")
    if not verificar_assinatura_rsa(api_pub_1, server_sig_data, str(body_cr.get("signature") or "")):
        raise RuntimeError("Assinatura do servidor TPM em /api/election/create/ falhou na verificação.")

    transitions: list[str] = []
    invariance_records: list[tuple[str, ElectionSnapshot, ElectionSnapshot, list[str]]] = []
    m5_runs: list[CheckResult] = []
    lifecycle_notes: list[str] = []

    snap_created = capturar_snapshot_eleicao(db, election_id)
    transitions.append(snap_created.status)

    # --- Fase 1: CREATED ---
    before = capturar_snapshot_eleicao(db, election_id)
    c_m1 = auditar_fase_created(
        args.base_url, snap_created, api_pub_1, api_pub_2, signer, signer.public_pem, election_priv, None, auth_token
    )
    c_m5_created = auditar_criptografia_e_controle_acesso(
        args.base_url,
        snap_created,
        api_pub_1,
        signer,
        signer.public_pem,
        election_priv,
        args.non_creator_token,
        args.strict_auth,
        auth_token=auth_token,
        run_plaintext=True,
        run_access_control=False,
        probe_available_auth=False,
    )
    after = capturar_snapshot_eleicao(db, election_id)
    invariance_records.append(("CREATED", before, after, verificar_invariancia(before, after, "CREATED")))
    m5_runs.append(c_m5_created)

    # --- Transição legítima: CREATED -> STARTED ---
    print(f"[FSM] Iniciando eleição #{election_id} (CREATED -> STARTED)...")
    since_ts = time.time()
    start_pl = {"msg": "START_ELECTION", "keyHandle": key_handle, "nonceClient2": f"fsm-start-{uuid.uuid4().hex[:8]}"}
    start_pl["election_signature"] = assinar_eleicao(election_priv, start_pl)
    code_st, body_st = _post_desktop(
        args.base_url, "/api/election/start/", api_pub_1, start_pl, signer=signer, auth_token=auth_token
    )
    if code_st != 200:
        raise RuntimeError(f"Falha ao iniciar eleição #{election_id} (HTTP {code_st}): {body_st}")

    tokens_map = capturar_tokens_email(args.sent_emails_dir, title, since_ts)
    prepared_before_close: dict[str, Any] | None = None
    late_vote_token: str | None = None

    if len(tokens_map) >= 3:
        t1 = tokens_map.get(voters_emails[0].lower())
        t2 = tokens_map.get(voters_emails[1].lower())
        t3 = tokens_map.get(voters_emails[2].lower())
        if t1:
            req1_code, req1_body, prep1 = solicitar_cedula_mobile(args.base_url, api_pub_2, t1, choice_index=0)
            if req1_code != 200 or prep1 is None:
                raise RuntimeError(f"Eleitor 1 falhou em /vote/request/ (HTTP {req1_code}): {req1_body}")
            cast1_code, cast1_body = depositar_voto_mobile(args.base_url, api_pub_2, prep1)
            if cast1_code != 200 or not isinstance(cast1_body, dict) or cast1_body.get("status") != "CONFIRMED":
                raise RuntimeError(f"Eleitor 1 falhou em /vote/cast/ (HTTP {cast1_code}): {cast1_body}")
            lifecycle_notes.append("Eleitor 1 votou normalmente em STARTED (1 cédula na urna).")
        if t2:
            req2_code, _, prep2 = solicitar_cedula_mobile(args.base_url, api_pub_2, t2, choice_index=1)
            if req2_code == 200 and prep2 is not None:
                prepared_before_close = prep2
                lifecycle_notes.append("Eleitor 2 obteve id_voto em STARTED para tentativa de depósito tardio pós-CLOSE.")
        if t3:
            late_vote_token = t3
    else:
        lifecycle_notes.append(
            f"Tokens não capturados em {args.sent_emails_dir} (encontrados={len(tokens_map)}); "
            "ataques com token mobile tardio foram pulados."
        )

    snap_started = capturar_snapshot_eleicao(db, election_id)
    transitions.append(snap_started.status)

    # --- Fase 2: STARTED ---
    before = capturar_snapshot_eleicao(db, election_id)
    c_m2 = auditar_fase_started(
        args.base_url, snap_started, api_pub_1, signer, signer.public_pem, election_priv, auth_token
    )
    c_m5_started = auditar_criptografia_e_controle_acesso(
        args.base_url,
        snap_started,
        api_pub_1,
        signer,
        signer.public_pem,
        election_priv,
        args.non_creator_token,
        args.strict_auth,
        auth_token=auth_token,
        run_plaintext=False,
        run_access_control=True,
        probe_available_auth=True,
    )
    after = capturar_snapshot_eleicao(db, election_id)
    invariance_records.append(("STARTED", before, after, verificar_invariancia(before, after, "STARTED")))
    m5_runs.append(c_m5_started)

    # --- Transição legítima: STARTED -> CLOSED ---
    print(f"[FSM] Fechando eleição #{election_id} (STARTED -> CLOSED)...")
    close_pl = {"msg": "CLOSE_ELECTION", "keyHandle": key_handle, "nonceClient3": f"fsm-close-{uuid.uuid4().hex[:8]}"}
    close_pl["election_signature"] = assinar_eleicao(election_priv, close_pl)
    code_cl, body_cl = _post_desktop(
        args.base_url, "/api/election/close/", api_pub_1, close_pl, signer=signer, auth_token=auth_token
    )
    if code_cl != 200:
        raise RuntimeError(f"Falha ao fechar eleição #{election_id} (HTTP {code_cl}): {body_cl}")

    snap_closed = capturar_snapshot_eleicao(db, election_id)
    transitions.append(snap_closed.status)

    # --- Fase 3: CLOSED ---
    before = capturar_snapshot_eleicao(db, election_id)
    c_m3 = auditar_fase_closed(
        args.base_url,
        snap_closed,
        api_pub_1,
        api_pub_2,
        signer,
        signer.public_pem,
        election_priv,
        prepared_before_close,
        late_vote_token,
        auth_token,
    )
    c_m5_closed = auditar_criptografia_e_controle_acesso(
        args.base_url,
        snap_closed,
        api_pub_1,
        signer,
        signer.public_pem,
        election_priv,
        args.non_creator_token,
        args.strict_auth,
        auth_token=auth_token,
        run_plaintext=False,
        run_access_control=True,
        probe_available_auth=False,
    )
    after = capturar_snapshot_eleicao(db, election_id)
    invariance_records.append(("CLOSED", before, after, verificar_invariancia(before, after, "CLOSED")))
    m5_runs.append(c_m5_closed)

    # --- Transição legítima: CLOSED -> TALLIED ---
    print(f"[FSM] Apurando eleição #{election_id} (CLOSED -> TALLIED)...")
    code_tv, body_tv = _post_desktop(
        args.base_url,
        "/api/election/tally/votes/",
        api_pub_1,
        {"msg": "FETCH_VOTES_FOR_TALLY", "keyHandle": key_handle, "nonceClient": f"fsm-tv-{uuid.uuid4().hex[:8]}"},
        signer=signer,
        auth_token=auth_token,
    )
    if code_tv != 200 or not isinstance(body_tv, dict):
        raise RuntimeError(f"Falha ao obter votos para apuração #{election_id} (HTTP {code_tv}): {body_tv}")

    results, tally_hash = computar_apuracao_canonica(
        raw_votes=body_tv.get("votes", []),
        questions_meta=body_tv.get("questions", []),
        total_voters=int(body_tv.get("total_voters", 3)),
        key_handle=key_handle,
        election_priv=election_priv,
    )
    code_tl, body_tl = _post_desktop(
        args.base_url,
        "/api/election/tally/",
        api_pub_1,
        {
            "msg": "SUBMIT_TALLY",
            "keyHandle": key_handle,
            "tally_hash": tally_hash,
            "private_key": election_priv_pem,
            "results": results,
            "nonceClient": f"fsm-tl-{uuid.uuid4().hex[:8]}",
        },
        signer=signer,
        auth_token=auth_token,
    )
    if code_tl != 200:
        raise RuntimeError(f"Falha ao apurar eleição #{election_id} (HTTP {code_tl}): {body_tl}")

    snap_tallied = capturar_snapshot_eleicao(db, election_id)
    transitions.append(snap_tallied.status)

    # --- Fase 4: TALLIED ---
    before = capturar_snapshot_eleicao(db, election_id)
    c_m4 = auditar_fase_tallied(
        args.base_url,
        snap_tallied,
        api_pub_1,
        api_pub_2,
        signer,
        signer.public_pem,
        election_priv,
        prepared_before_close,
        late_vote_token,
        auth_token,
    )
    after = capturar_snapshot_eleicao(db, election_id)
    invariance_records.append(("TALLIED", before, after, verificar_invariancia(before, after, "TALLIED")))

    c_m5 = _combine_m5_results(m5_runs)
    c_m6 = auditar_invariancia_banco(invariance_records, lifecycle_transitions=transitions)
    if lifecycle_notes:
        c_m6.details.extend(lifecycle_notes)

    meta = {
        "mode": "full-lifecycle",
        "election_id": election_id,
        "title": title,
        "status": snap_tallied.status,
        "key_handle": key_handle,
        "creator_email": creator_user.get("email"),
        "signer": signer.backend_label,
        "transitions": transitions,
    }
    return [c_m1, c_m2, c_m3, c_m4, c_m5, c_m6], meta


# ==============================================================================
# Interface CLI e Relatório Final
# ==============================================================================
def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Teste 3 (Eixo 1): Inviolabilidade da Máquina de Estados da API.",
    )
    parser.add_argument("--election-id", type=int, help="ID de eleição existente para auditoria não-destrutiva.")
    parser.add_argument(
        "--full-lifecycle",
        action="store_true",
        help="Cria eleição efêmera e testa todas as fases (CREATED -> STARTED -> CLOSED -> TALLIED).",
    )
    parser.add_argument("--list", action="store_true", help="Lista eleições cadastradas no banco e sai.")
    parser.add_argument("--dry-run", action="store_true", help="Valida chaves, envelopes TPM e assinaturas localmente.")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help=f"URL base da API (padrão: {DEFAULT_BASE_URL}).")
    parser.add_argument("--vote-token", help="Token de votação opcional para testar bloqueio por fase.")
    parser.add_argument("--auth-token", help="Token Knox do administrador criador.")
    parser.add_argument("--admin-email", help="E-mail do administrador para login automático via /api/auth/login/.")
    parser.add_argument("--admin-password", help="Senha do administrador para login automático via /api/auth/login/.")
    parser.add_argument("--admin-totp", help="Código TOTP de 6 dígitos para login automático via /api/auth/login/.")
    parser.add_argument("--device-id", help="Device ID da máquina Desktop para login automático.")
    parser.add_argument("--non-creator-token", help="Token Knox opcional de usuário não-criador para teste de privilégio.")
    parser.add_argument(
        "--strict-auth",
        action="store_true",
        help="Reprova (FALHOU em vez de ALERTA) se rotas administrativas aceitarem requisições sem header Authorization.",
    )
    parser.add_argument("--se-keys", type=Path, default=SE_KEYS_PATH, help=f"Caminho de se_keys_info.json (padrão: {SE_KEYS_PATH}).")
    parser.add_argument(
        "--client-key",
        type=Path,
        default=DEFAULT_CLIENT_KEY_PATH,
        help=f"Caminho de client_key.json do Desktop (padrão: {DEFAULT_CLIENT_KEY_PATH}).",
    )
    parser.add_argument(
        "--sent-emails-dir",
        type=Path,
        default=DEFAULT_SENT_EMAILS_DIR,
        help=f"Diretório sent_emails para captura de tokens (padrão: {DEFAULT_SENT_EMAILS_DIR}).",
    )
    parser.add_argument("--db-url", help="DSN PostgreSQL explícito (ex.: postgresql://user:pass@host:5432/db).")
    parser.add_argument("--sqlite", type=Path, help="Caminho explícito para um banco SQLite.")
    parser.add_argument("--env-file", type=Path, default=DEFAULT_ENV_PATH, help=f"Arquivo .env do backend (padrão: {DEFAULT_ENV_PATH}).")
    parser.add_argument("--json-out", type=Path, help="Grava relatório estruturado em JSON neste caminho.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    if args.dry_run:
        try:
            return executar_dry_run(args)
        except Exception as exc:
            print(f"[DRY-RUN] Erro: {exc}", file=sys.stderr)
            return 2

    try:
        db = DBAdapter.connect(db_url=args.db_url, sqlite_path=args.sqlite, env_path=args.env_file)
    except Exception as exc:
        print(f"Erro ao conectar ao banco de dados: {exc}", file=sys.stderr)
        return 2

    try:
        if args.list:
            listar_eleicoes_resumo(db)
            return 0

        if not args.full_lifecycle and args.election_id is None:
            print("Uso:")
            print("  python3 maquinaEstados.py --election-id <ID> [--vote-token TOKEN]")
            print("  python3 maquinaEstados.py --full-lifecycle")
            print("  python3 maquinaEstados.py --dry-run")
            print("  python3 maquinaEstados.py --list")
            listar_eleicoes_resumo(db)
            return 2

        if args.full_lifecycle and args.election_id is not None:
            print("Erro: informe apenas --election-id OU --full-lifecycle.", file=sys.stderr)
            return 2

        if args.full_lifecycle:
            checks, meta = executar_ciclo_completo(args, db)
        else:
            checks, meta = executar_eleicao_existente(args, db)

        print("\n" + "=" * 78)
        print("AUDITORIA DA MÁQUINA DE ESTADOS DA API (EIXO 1 - TESTE 3)")
        print("=" * 78)
        print(f"Modo    : {meta.get('mode')}")
        print(f"Eleição : #{meta.get('election_id')} - {meta.get('title')} [status={meta.get('status')}]")
        print(f"Signer  : {meta.get('signer')}")
        print(f"Banco   : {db.description}")
        print(f"API     : {args.base_url}")
        for note in db.notes:
            print(f"Aviso   : {note}")
        print("-" * 78)

        for chk in checks:
            print(f"[{chk.status:<6}] {chk.code} - {chk.title}: {chk.summary}")
            for line in chk.details:
                print(f"           {line}")

        print("=" * 78)
        has_fail = any(c.status == "FALHOU" for c in checks)
        has_alert = any(c.status == "ALERTA" for c in checks)
        executed = any(c.status in ("PASSOU", "FALHOU", "ALERTA") for c in checks)

        if has_fail or not executed:
            verdict = "REPROVADO"
            exit_code = 1
        elif has_alert:
            verdict = "APROVADO COM ALERTAS"
            exit_code = 1 if args.strict_auth else 0
        else:
            verdict = "APROVADO"
            exit_code = 0

        print(f"Resultado: {verdict}")

        if args.json_out:
            report = {
                "meta": meta,
                "db": db.description,
                "base_url": args.base_url,
                "verdict": verdict,
                "checks": [asdict(c) for c in checks],
            }
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
            print(f"Relatório JSON salvo em: {args.json_out}")

        return exit_code
    except Exception as exc:
        print(f"Erro durante execução do ensaio: {exc}", file=sys.stderr)
        return 2
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
