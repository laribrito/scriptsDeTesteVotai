"""
Teste 1: Resistência a Ataques Man-in-the-Middle (MitM) e Certificate Pinning (Eixo 2)

Avalia as aplicações clientes (votaai-desktop e projeto-react-native) roteando o
tráfego através do proxy Burp Suite real com sua CA espúria (PortSwigger CA)
instalada na raiz de confiança do sistema operacional, submetendo ambas aos fluxos de:
  1. Autenticação
  2. Recebimento de parâmetros
  3. Envio de votos / operações eleitorais

Critério de validação:
  Aprovado somente se ambos os clientes abortarem imediatamente a conexão TLS,
  registrando falha de validação criptográfica e impedindo que qualquer requisição
  ou carga útil atravesse o Burp Suite até o servidor.
"""

from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import http.client
import http.server
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import warnings
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

# A CA padrão do Burp Suite coloca "PortSwigger" (11 chars) no campo C=CountryName
warnings.filterwarnings("ignore", message="Country names should be two characters", category=UserWarning)

# ==============================================================================
# Configuração padrão do ensaio (Burp Suite real + repositórios locais)
# ==============================================================================
DEFAULT_BURP_PROXY = "127.0.0.1:8080"
DEFAULT_BURP_CA = Path("/home/debrito/Programação/configBurp/burp-ca.crt")
DEFAULT_BACKEND_URL = "http://127.0.0.1:8000"
DEFAULT_TARGET_HOST = "localhost"

BACKEND_DIR = Path("/home/debrito/Programação/votaai-backend")
DESKTOP_DIR = Path("/home/debrito/Programação/votaai-desktop")
DESKTOP_VENV_PYTHON = DESKTOP_DIR / ".venv" / "bin" / "python"
MOBILE_DIR = Path("/home/debrito/Programação/projeto-react-native")
SE_KEYS_PATH = BACKEND_DIR / "se_keys_info.json"
CANARY_KNOX_TOKEN = "CANARY_KNOX_TOKEN_BURP_MITM_TEST"
SENSITIVE_BODY_CANARIES = (
    "CanaryPassword!123",
    "mitm.probe@uesc.br",
    "CANARY_VOTE_TOKEN",
    "CANARY_CONTENT",
    "CANARY_NONCE_",
    "CANARY_KEY",
    "CANARY-DEV",
    "n-req-1",
    "n-cast-1",
    "VOTE-0",
)


@dataclass
class CheckResult:
    code: str
    title: str
    status: str  # "PASSOU" | "FALHOU" | "ALERTA" | "N/A"
    summary: str
    details: list[str] = field(default_factory=list)


# ==============================================================================
# Certificado TLS legítimo do Origin e Ponte HTTPS -> Backend Django
# ==============================================================================
def compute_spki_pin(cert: x509.Certificate) -> str:
    spki = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return "sha256/" + base64.b64encode(hashlib.sha256(spki).digest()).decode("ascii")


def gerar_cert_origin(tmp_dir: Path, target_host: str) -> tuple[Path, Path, str]:
    """Gera certificado X.509 v3 legítimo para o servidor HTTPS local e retorna (cert_pem, key_pem, spki_pin)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VotaAI Origin"), x509.NameAttribute(NameOID.COMMON_NAME, target_host)])
    now = datetime.datetime.now(datetime.timezone.utc)
    sans: list[x509.GeneralName] = []
    for h in dict.fromkeys([target_host, "localhost", "127.0.0.1"]):
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(h)))
        except ValueError:
            sans.append(x509.DNSName(h))
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=True,
                                     data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                     crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(ski, critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_dir / "origin_cert.pem"
    key_path = tmp_dir / "origin_key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return cert_path, key_path, compute_spki_pin(cert)


def _inspect_json_envelope(raw: bytes) -> tuple[bool, bool]:
    """Retorna (is_hybrid_envelope, is_cleartext_json) para o payload HTTP inspecionado."""
    if not raw.strip():
        return False, False
    try:
        parsed = json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        return False, False
    if isinstance(parsed, dict) and {"encrypted_payload", "encrypted_aes_key", "iv", "tag"} <= set(parsed.keys()):
        return True, False
    return False, True


class OriginHTTPSBridge:
    """Servidor HTTPS local que encaminha requisições ao backend e contabiliza o que atravessou o Burp."""

    def __init__(self, cert_path: Path, key_path: Path, backend_url: str, host: str = "127.0.0.1", port: int = 0) -> None:
        self.backend_url = backend_url.rstrip("/")
        self._lock = threading.Lock()
        self.requests: list[dict[str, Any]] = []
        parent = self

        class _SilentThreadingHTTPServer(http.server.ThreadingHTTPServer):
            allow_reuse_address = True
            daemon_threads = True

            def handle_error(self, request: Any, client_address: Any) -> None:
                pass  # Silencia abortos TLS esperados quando o cliente rejeita a CA do Burp

        class _Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:
                return

            def _dispatch(self, method: str) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length > 0 else b""
                auth = self.headers.get("Authorization") or ""
                body_text = body.decode("utf-8", errors="replace")
                canary_leaked = (CANARY_KNOX_TOKEN in auth) or (CANARY_KNOX_TOKEN in body_text)
                is_hybrid, _ = _inspect_json_envelope(body)
                plain_leaks = [c for c in SENSITIVE_BODY_CANARIES if c in body_text]
                status, ctype, resp_body = parent._forward(method, self.path, dict(self.headers.items()), body)
                resp_hybrid, resp_cleartext = _inspect_json_envelope(resp_body)
                with parent._lock:
                    parent.requests.append({
                        "method": method,
                        "path": self.path.split("?", 1)[0],
                        "auth_exposed": bool(auth),
                        "canary_leaked": canary_leaked,
                        "body_len": len(body),
                        "status": status,
                        "is_hybrid_envelope": is_hybrid,
                        "body_plaintext_leaks": plain_leaks,
                        "resp_is_hybrid_envelope": resp_hybrid,
                        "resp_is_cleartext_json": resp_cleartext,
                    })
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(resp_body)))
                self.send_header("Connection", "close")
                self.end_headers()
                if resp_body:
                    self.wfile.write(resp_body)

            def do_GET(self) -> None:
                self._dispatch("GET")

            def do_POST(self) -> None:
                self._dispatch("POST")

        self._server = _SilentThreadingHTTPServer((host, port), _Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        self._server.socket = ctx.wrap_socket(self._server.socket, server_side=True)
        self.port = int(self._server.server_address[1])
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def _forward(self, method: str, path: str, headers: dict[str, str], body: bytes) -> tuple[int, str, bytes]:
        parsed = urllib.parse.urlparse(self.backend_url)
        try:
            conn_cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
            conn = conn_cls(parsed.hostname or "127.0.0.1", parsed.port or (443 if parsed.scheme == "https" else 8000), timeout=8.0)
            fwd_headers = {k: v for k, v in headers.items() if k.lower() not in ("host", "connection", "proxy-connection", "content-length", "accept-encoding")}
            fwd_headers["Host"] = parsed.netloc
            fwd_headers["Connection"] = "close"
            conn.request(method, path, body=body or None, headers=fwd_headers)
            resp = conn.getresponse()
            data = resp.read()
            ctype = resp.getheader("Content-Type") or "application/json; charset=utf-8"
            status = resp.status
            conn.close()
            return status, ctype, data
        except Exception:
            fallback = json.dumps({"status": "origin_fallback", "method": method, "path": path}).encode("utf-8")
            return 200, "application/json; charset=utf-8", fallback

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
# C0 / C1 — Verificação do Burp Suite real + Trust Store + Controle Baseline
# ==============================================================================
def _resolve_burp_ca(path: Path) -> Path | None:
    if path.is_file():
        return path
    alt = path.parent / "cacert.der"
    return alt if alt.is_file() else None


def verificar_ambiente_burp(burp_host: str, burp_port: int, burp_ca: Path) -> tuple[CheckResult, Path | None]:
    resolved_ca = _resolve_burp_ca(burp_ca)
    details: list[str] = []
    failures: list[str] = []

    try:
        with socket.create_connection((burp_host, burp_port), timeout=2.5):
            details.append(f"Proxy Burp acessível em {burp_host}:{burp_port}.")
    except OSError as exc:
        failures.append(f"Burp Suite não acessível em {burp_host}:{burp_port} ({exc}).")

    if resolved_ca is None:
        failures.append(f"Certificado CA do Burp não encontrado em {burp_ca} (nem cacert.der).")
    else:
        raw = resolved_ca.read_bytes()
        cert = x509.load_pem_x509_certificate(raw) if b"-----BEGIN CERTIFICATE-----" in raw else x509.load_der_x509_certificate(raw)
        details.append(f"CA do Burp carregada ({resolved_ca.name}): {cert.subject.rfc4514_string()} | SPKI={compute_spki_pin(cert)}")

    system_cas = ssl.create_default_context().get_ca_certs()
    portswigger_in_os = any("portswigger" in str(c.get("subject", "")).lower() for c in system_cas)
    details.append(f"PortSwigger CA presente na raiz de confiança do SO: {'sim' if portswigger_in_os else 'não'}")
    if not portswigger_in_os:
        failures.append("PortSwigger CA não encontrada no trust store padrão do SO (execute update-ca-certificates).")

    if failures:
        return CheckResult("C0", "Ambiente Burp Suite e CA na Raiz de Confiança do SO", "FALHOU", failures[0], failures + details), resolved_ca
    return CheckResult("C0", "Ambiente Burp Suite e CA na Raiz de Confiança do SO", "PASSOU", "Burp Suite ativo e PortSwigger CA confiada pelo SO.", details), resolved_ca


def _https_via_burp(
    burp_host: str, burp_port: int, target_host: str, origin_port: int, path: str,
    expected_spki_pin: str | None = None, headers: dict[str, str] | None = None,
) -> tuple[bool, int | None, str, str]:
    """Abre túnel CONNECT pelo Burp real usando o trust store real do SO e opcionalmente valida SPKI pinning."""
    sock = socket.create_connection((burp_host, burp_port), timeout=6.0)
    try:
        sock.sendall(f"CONNECT {target_host}:{origin_port} HTTP/1.1\r\nHost: {target_host}:{origin_port}\r\n\r\n".encode("ascii"))
        buf = bytearray()
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                return False, None, "Burp fechou conexão durante CONNECT.", ""
            buf.extend(chunk)
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(sock, server_hostname=target_host) as tls:
            der = tls.getpeercert(binary_form=True)
            peer = x509.load_der_x509_certificate(der)
            issuer_str = peer.issuer.rfc4514_string()
            actual_pin = compute_spki_pin(peer)
            if expected_spki_pin and actual_pin != expected_spki_pin:
                raise ssl.SSLCertVerificationError(f"TLS Pinning mismatch! expected={expected_spki_pin} actual={actual_pin} issuer={issuer_str}")
            req = [f"POST {path} HTTP/1.1\r\nHost: {target_host}:{origin_port}\r\nContent-Length: 2\r\nConnection: close\r\n".encode("ascii")]
            for k, v in (headers or {}).items():
                req.append(f"{k}: {v}\r\n".encode("latin-1"))
            req.append(b"\r\n{}")
            tls.sendall(b"".join(req))
            raw_resp = b""
            while True:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                raw_resp += chunk
            first = raw_resp.split(b"\r\n", 1)[0].decode("latin-1", errors="replace").split(" ")
            code = int(first[1]) if len(first) >= 2 and first[1].isdigit() else None
            return True, code, "", issuer_str
    except (ssl.SSLError, OSError) as exc:
        hint = " (verifique se Proxy -> Intercept está OFF no Burp)" if isinstance(exc, TimeoutError) else ""
        return False, None, f"{type(exc).__name__}: {exc}{hint}", ""
    finally:
        try:
            sock.close()
        except OSError:
            pass


def executar_controle_burp(burp_host: str, burp_port: int, target_host: str, bridge: OriginHTTPSBridge, origin_pin: str) -> CheckResult:
    idx0 = bridge.snapshot()
    ok_neg, code_neg, err_neg, issuer_neg = _https_via_burp(
        burp_host, burp_port, target_host, bridge.port, "/api/public/elections/",
        expected_spki_pin=None, headers={"Authorization": f"Token {CANARY_KNOX_TOKEN}"},
    )
    reqs_neg = bridge.since(idx0)
    neg_ok = ok_neg and ("portswigger" in issuer_neg.lower()) and len(reqs_neg) == 1

    idx1 = bridge.snapshot()
    ok_pos, _, err_pos, _ = _https_via_burp(
        burp_host, burp_port, target_host, bridge.port, "/api/public/elections/",
        expected_spki_pin=origin_pin, headers={"Authorization": f"Token {CANARY_KNOX_TOKEN}"},
    )
    reqs_pos = bridge.since(idx1)
    pos_ok = (not ok_pos) and ("mismatch" in err_pos.lower() or "ssl" in err_pos.lower()) and len(reqs_pos) == 0

    details = [
        f"Sem pinning (Burp MitM): ok={ok_neg}, HTTP={code_neg}, issuer='{issuer_neg}', reqs_origin={len(reqs_neg)}",
        f"Com SPKI pinning: abortado={not ok_pos}, reqs_origin={len(reqs_pos)}, erro='{err_pos}'",
    ]
    if neg_ok and pos_ok:
        return CheckResult("C1", "Controle Baseline no Burp Suite Real", "PASSOU", "Burp intercepta cliente sem pinning (issuer PortSwigger CA) e cliente com SPKI pinning aborta com 0 reqs.", details)
    return CheckResult("C1", "Controle Baseline no Burp Suite Real", "FALHOU", f"Falha na calibração com Burp ({err_neg or err_pos}).", details)


# ==============================================================================
# C2 — Cliente Desktop Real (votaai-desktop HttpClient) via Burp Suite
# ==============================================================================
_DESKTOP_PROBE = r"""
import json, os
from app.services.http_client import HttpClient

os.environ["API_BASE_URL"] = os.environ["MITM_TARGET_URL"]
HttpClient.set_auth_token(os.environ["MITM_CANARY_TOKEN"])
client = HttpClient(timeout=10)
flows = [
    ("autenticacao", "/api/auth/login/", {"username": "mitm.probe@uesc.br", "password": "CanaryPassword!123", "totp_code": "123456", "device_id": "CANARY-DEV"}),
    ("parametros", "/api/election/available/", {"msg": "FETCH_AVAILABLE", "nonceClient1": "CANARY_NONCE_1"}),
    ("voto", "/api/election/tally/votes/", {"msg": "FETCH_VOTES_FOR_TALLY", "keyHandle": "CANARY_KEY", "nonceClient": "CANARY_NONCE_2"}),
    ("voto", "/api/vote/cast/", {"token": "CANARY_VOTE_TOKEN", "content": "CANARY_CONTENT", "nonce": "CANARY_NONCE_3"}),
]
out = [{"flow": cat, "endpoint": ep, "response": client.post(ep, payload)} for cat, ep, payload in flows]
print("DESKTOP_MITM_JSON:" + json.dumps(out, ensure_ascii=False))
"""


def executar_teste_desktop(
    burp_host: str, burp_port: int, target_host: str, bridge: OriginHTTPSBridge, desktop_py: Path,
) -> tuple[CheckResult, CheckResult]:
    http_client_py = DESKTOP_DIR / "app" / "services" / "http_client.py"
    initial_key_json = DESKTOP_DIR / "app" / "resources" / "initial_key.json"
    env_file = DESKTOP_DIR / ".env"

    tls_gaps: list[str] = []
    app_pin_ok = False
    if http_client_py.is_file():
        src = http_client_py.read_text(encoding="utf-8")
        if "SSLContext" not in src:
            tls_gaps.append("http_client.py não cria ssl.SSLContext customizado em urlopen().")
        if not re.search(r"(getpeercert|pin_sha256|spki|certificate_pin)", src, re.IGNORECASE):
            tls_gaps.append("http_client.py não implementa TLS Certificate Pinning.")
        if not re.search(r"scheme\s*!=\s*['\"]https['\"]", src, re.IGNORECASE):
            tls_gaps.append("http_client.py aceita HTTP em texto claro (default='http://127.0.0.1:8000').")
        app_pin_ok = "encrypt_payload" in src and "EncryptionController" in src
    if env_file.is_file():
        m = re.search(r"^\s*API_BASE_URL\s*=\s*(.+)$", env_file.read_text(encoding="utf-8"), re.MULTILINE)
        if m and m.group(1).strip().lower().startswith("http://"):
            tls_gaps.append(f".env define API_BASE_URL sem TLS: '{m.group(1).strip()}'.")

    has_static_server_key = False
    if initial_key_json.is_file():
        try:
            kdata = json.loads(initial_key_json.read_text(encoding="utf-8"))
            klist = kdata if isinstance(kdata, list) else [kdata]
            has_static_server_key = any(k.get("KeyName") == "VotaAI_SecureKey_1" and k.get("PublicKeyBase64") for k in klist)
        except Exception:
            has_static_server_key = False

    py_bin = desktop_py if desktop_py.is_file() else Path(sys.executable)
    env = os.environ.copy()
    proxy_url = f"http://{burp_host}:{burp_port}"
    env.update({
        "PYTHONPATH": str(DESKTOP_DIR),
        "API_BASE_URL": f"https://{target_host}:{bridge.port}",
        "MITM_TARGET_URL": f"https://{target_host}:{bridge.port}",
        "MITM_CANARY_TOKEN": CANARY_KNOX_TOKEN,
        "HTTP_PROXY": proxy_url, "HTTPS_PROXY": proxy_url,
        "http_proxy": proxy_url, "https_proxy": proxy_url,
        "NO_PROXY": "", "no_proxy": "",
    })
    # Usa exclusivamente o trust store real do sistema operacional (sem sobrescrever SSL_CERT_FILE)
    env.pop("SSL_CERT_FILE", None)
    env.pop("REQUESTS_CA_BUNDLE", None)

    idx0 = bridge.snapshot()
    proc = subprocess.run([str(py_bin), "-c", _DESKTOP_PROBE], cwd=str(DESKTOP_DIR), env=env, capture_output=True, text=True, timeout=45)
    reqs_origin = bridge.since(idx0)

    items: list[dict[str, Any]] = []
    for line in (proc.stdout or "").splitlines():
        if line.startswith("DESKTOP_MITM_JSON:"):
            items = json.loads(line[len("DESKTOP_MITM_JSON:") :])

    if proc.returncode != 0 or not items:
        err = CheckResult("C2A", "Desktop | Camada de Transporte (TLS / Certificate Pinning via Burp)", "FALHOU", f"Erro ao executar Desktop HttpClient (rc={proc.returncode}).", [proc.stdout[:300], proc.stderr[:300]])
        err_app = CheckResult("C2B", "Desktop | Camada de Aplicação (Static Public Key Pinning)", "FALHOU", "Não avaliado devido a erro de execução do Desktop.")
        return err, err_app

    req_by_path = {r["path"]: r for r in reqs_origin}
    tls_details = [
        "Escopo desta camada: impedir o handshake TLS quando o proxy apresenta certificado da PortSwigger CA (trabalhos futuros).",
        *tls_gaps,
    ]
    all_aborted = True
    for it in items:
        resp = it.get("response") or {}
        raw_msg = resp.get("mensagem") or resp.get("dados") or resp
        msg = json.dumps(raw_msg, ensure_ascii=False) if isinstance(raw_msg, (dict, list)) else str(raw_msg)
        aborted = any(k in msg.lower() for k in ("certificate", "ssl", "tls", "pin", "handshake"))
        if not aborted:
            all_aborted = False
        ep_req = req_by_path.get(it["endpoint"], {})
        auth_tag = " | auth_knox_exposto=sim" if ep_req.get("auth_exposed") else ""
        http_tag = f" (HTTP {ep_req['status']})" if ep_req.get("status") else ""
        tls_details.append(f"Fluxo [{it['flow']}] POST {it['endpoint']}: {'BLOQUEADO' if aborted else 'ATRAVESSOU BURP'}{http_tag}{auth_tag} -> {msg[:130]}")

    canary_leaks = sum(1 for r in reqs_origin if r["canary_leaked"])
    tls_details.append(f"O que o Burp inspecionou na camada HTTP/TLS: {len(reqs_origin)} requisição(ões) (rotas, métodos, status) e header 'Authorization: Token ...' vazado em {canary_leaks} rota(s).")

    if all_aborted and len(reqs_origin) == 0 and not tls_gaps:
        c2a = CheckResult("C2A", "Desktop | Camada de Transporte (TLS / Certificate Pinning via Burp)", "PASSOU", "votaai-desktop abortou TLS nos 3 fluxos e 0 requisições atravessaram o Burp.", tls_details)
    else:
        c2a = CheckResult("C2A", "Desktop | Camada de Transporte (TLS / Certificate Pinning via Burp)", "FALHOU", f"Sem TLS Certificate Pinning: aceitou PortSwigger CA e trafegou {len(reqs_origin)} requisição(ões) (Authorization vazado em {canary_leaks}).", tls_details)

    # C2B — Camada de Aplicação (Static Public Key Pinning com initial_key.json)
    hybrid_posts = [r for r in reqs_origin if r["is_hybrid_envelope"]]
    plain_body_leaks = [(r["path"], r["body_plaintext_leaks"]) for r in reqs_origin if r["body_plaintext_leaks"]]
    app_details = [
        "Escopo desta camada: chave pública RSA estática do servidor (VotaAI_SecureKey_1) embutida no cliente com cifragem híbrida AES-256-GCM + RSA (Sign-then-Encrypt).",
        f"Estático: initial_key.json (VotaAI_SecureKey_1)={'presente' if has_static_server_key else 'AUSENTE'}, HttpClient->encrypt_payload={'ativo' if app_pin_ok else 'AUSENTE'}.",
    ]
    if reqs_origin:
        app_details.append(
            f"Dinâmico no payload pós-Burp: {len(hybrid_posts)}/{len(reqs_origin)} POSTs em envelope híbrido "
            f"(encrypted_payload+encrypted_aes_key+iv+tag) | canários em claro no corpo: {len(plain_body_leaks)}."
        )
    else:
        app_details.append("Dinâmico: 0 requisições alcançaram o Origin (canal bloqueado já na camada TLS).")
    app_details.extend([
        "O que PROTEGE mesmo com TLS interceptado: credenciais (senha/TOTP), device_id, parâmetros e payloads JSON internos permanecem ilegíveis ao Burp.",
        "O que NÃO PROTEGE sem Certificate Pinning: conexão TLS, URLs/métodos, status HTTP e cabeçalho 'Authorization: Token ...' (fora do corpo AES-GCM).",
    ])

    c2b_ok = has_static_server_key and app_pin_ok and (len(hybrid_posts) == len(reqs_origin)) and (len(plain_body_leaks) == 0)
    c2b = CheckResult(
        "C2B",
        "Desktop | Camada de Aplicação (Static Public Key Pinning)",
        "PASSOU" if c2b_ok else "FALHOU",
        (
            f"Static Public Key Pinning protegeu {len(hybrid_posts)}/{len(reqs_origin)} corpos sensíveis em envelope AES-GCM+RSA (0 vazamentos de corpo)."
            if c2b_ok
            else f"Falha na proteção de camada de aplicação (static_key={has_static_server_key}, plain_leaks={plain_body_leaks})."
        ),
        app_details,
    )
    return c2a, c2b


# ==============================================================================
# C3 — Cliente Móvel (projeto-react-native OkHttp + BuildConfig) via Burp Suite
# ==============================================================================
_OKHTTP_PROBE_JAVA = r"""
import okhttp3.*;
import javax.net.ssl.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.*;
import java.util.concurrent.TimeUnit;

public class OkHttpBurpProbe {
    private static String esc(String s) {
        return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "");
    }

    private static SSLContext sslFromCa(String caPath, X509TrustManager[] outTm) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        int i = 0;
        try (InputStream is = new BufferedInputStream(new FileInputStream(caPath))) {
            for (Certificate c : cf.generateCertificates(is)) ks.setCertificateEntry("ca_" + (i++), c);
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        for (TrustManager tm : tmf.getTrustManagers()) {
            if (tm instanceof X509TrustManager) { outTm[0] = (X509TrustManager) tm; break; }
        }
        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, new TrustManager[]{outTm[0]}, null);
        return sc;
    }

    private static OkHttpClient makeClient(String burpHost, int burpPort, String caPath, String pinHost, String pin1, String pin2, List<String> ev) throws Exception {
        X509TrustManager[] tm = new X509TrustManager[1];
        SSLContext sc = sslFromCa(caPath, tm);
        OkHttpClient.Builder b = new OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS).readTimeout(10, TimeUnit.SECONDS)
            .proxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress(burpHost, burpPort)))
            .sslSocketFactory(sc.getSocketFactory(), tm[0])
            .eventListener(new okhttp3.EventListener() {
                @Override public void secureConnectStart(Call c) { ev.add("secureConnectStart"); }
                @Override public void secureConnectEnd(Call c, Handshake h) { ev.add("secureConnectEnd:" + (h != null ? h.tlsVersion() : "null")); }
                @Override public void connectFailed(Call c, InetSocketAddress a, Proxy p, Protocol pr, IOException e) { ev.add("connectFailed:" + e.getClass().getSimpleName()); }
                @Override public void callFailed(Call c, IOException e) { ev.add("callFailed:" + e.getClass().getSimpleName()); }
            });
        if (!pinHost.trim().isEmpty() && !pin1.trim().isEmpty()) {
            CertificatePinner.Builder cp = new CertificatePinner.Builder().add(pinHost.trim(), pin1.trim());
            if (!pin2.trim().isEmpty()) cp.add(pinHost.trim(), pin2.trim());
            b.certificatePinner(cp.build());
        }
        return b.build();
    }

    private static String call(OkHttpClient cli, List<String> ev, String mode, String flow, String url, String method, String bodyJson) {
        ev.clear();
        Request.Builder rb = new Request.Builder().url(url).header("Accept", "application/json");
        if ("POST".equals(method)) rb.post(RequestBody.create(bodyJson, MediaType.get("application/json; charset=utf-8")));
        else rb.get();
        int code = -1; String errCls = "", errMsg = "";
        try (Response r = cli.newCall(rb.build()).execute()) {
            code = r.code();
            if (r.body() != null) r.body().string();
        } catch (Throwable t) {
            errCls = t.getClass().getName();
            errMsg = String.valueOf(t.getMessage());
        }
        return "{\"mode\":\"" + mode + "\",\"flow\":\"" + flow + "\",\"method\":\"" + method + "\",\"url\":\"" + esc(url)
            + "\",\"http_status\":" + code + ",\"err_class\":\"" + esc(errCls) + "\",\"err_msg\":\"" + esc(errMsg)
            + "\",\"events\":\"" + esc(String.join(" | ", ev)) + "\"}";
    }

    public static void main(String[] args) throws Exception {
        String mode = args[0], burpHost = args[1];
        int burpPort = Integer.parseInt(args[2]);
        String caPath = args[3], baseUrl = args[4], pinHost = args[5], pin1 = args[6], pin2 = args[7];
        String reqBody = new String(Base64.getDecoder().decode(args[8]), StandardCharsets.UTF_8);
        String castBody = new String(Base64.getDecoder().decode(args[9]), StandardCharsets.UTF_8);
        List<String> ev = new ArrayList<>();
        OkHttpClient cli = makeClient(burpHost, burpPort, caPath, pinHost, pin1, pin2, ev);
        List<String> out = new ArrayList<>();
        if ("real".equals(mode)) {
            out.add(call(cli, ev, "real", "autenticacao", baseUrl + "/api/vote/request/", "POST", reqBody));
            out.add(call(cli, ev, "real", "parametros", baseUrl + "/api/public/elections/", "GET", ""));
            out.add(call(cli, ev, "real", "voto", baseUrl + "/api/vote/cast/", "POST", castBody));
        } else {
            out.add(call(cli, ev, "diag", "parametros", baseUrl + "/api/public/elections/", "GET", ""));
        }
        System.out.println("[" + String.join(",", out) + "]");
    }
}
"""


def _load_mobile_build_pins(build_type: str) -> tuple[str, str, str, list[str]]:
    bc_path = MOBILE_DIR / "android" / "app" / "build" / "generated" / "source" / "buildConfig" / build_type / "com" / "meuapptestecripto" / "BuildConfig.java"
    fields: dict[str, str] = {}
    if bc_path.is_file():
        for m in re.finditer(r'public\s+static\s+final\s+(?:String|boolean)\s+([A-Z0-9_]+)\s*=\s*"?([^";]+)"?\s*;', bc_path.read_text(encoding="utf-8")):
            fields[m.group(1)] = m.group(2)

    gaps: list[str] = []
    nsc_path = MOBILE_DIR / "android" / "app" / "src" / "main" / "res" / "xml" / "network_security_config.xml"
    if nsc_path.is_file():
        xml_txt = nsc_path.read_text(encoding="utf-8")
        root = ET.fromstring(xml_txt)
        base_cfg = root.find("base-config")
        if base_cfg is not None and base_cfg.attrib.get("cleartextTrafficPermitted") == "true":
            gaps.append("network_security_config.xml permite cleartext (<base-config cleartextTrafficPermitted=\"true\">).")
        if not any(d.find("pin-set") is not None for d in root.findall("domain-config")):
            gaps.append("network_security_config.xml sem <pin-set> ativo (bloco comentado).")

    h, p1, p2 = fields.get("SSL_PINNING_HOST", ""), fields.get("SSL_PINNING_SHA256", ""), fields.get("SSL_PINNING_BACKUP_SHA256", "")
    if not h or not p1:
        gaps.append(f"BuildConfig ({build_type}) com SSL_PINNING_HOST='{h}' e SSL_PINNING_SHA256='{p1}' vazios (PinningOkHttpClientFactory em fail-open).")
    api_cfg = MOBILE_DIR / "src" / "services" / "api" / "api.config.ts"
    if api_cfg.is_file() and "http://${LOCAL_LAN_HOST}:8000" in api_cfg.read_text(encoding="utf-8"):
        gaps.append("api.config.ts define DEFAULT_API_BASE_URL em HTTP cleartext (http://...).")
    return h, p1, p2, gaps


def _find_okhttp_jars() -> list[Path]:
    base = Path.home() / ".gradle" / "caches" / "modules-2" / "files-2.1"
    picks = [
        sorted((base / "com.squareup.okhttp3").rglob("okhttp-4.12*.jar")),
        sorted((base / "com.squareup.okio").rglob("okio-jvm-3.6*.jar")),
        sorted((base / "org.jetbrains.kotlin").rglob("kotlin-stdlib-2.2.10.jar")),
    ]
    return [p[-1] for p in picks if p]


def _build_mobile_bodies() -> tuple[str, str]:
    pub: rsa.RSAPublicKey | None = None
    if SE_KEYS_PATH.is_file():
        keys = json.loads(SE_KEYS_PATH.read_text(encoding="utf-8"))
        entry = next((k for k in keys if k.get("KeyName") == "VotaAI_SecureKey_2"), None)
        if entry and entry.get("PublicKeyBase64"):
            blob = base64.b64decode(entry["PublicKeyBase64"])
            _, _, cb_e, cb_m, _, _ = struct.unpack("<IIIIII", blob[:24])
            pub = rsa.RSAPublicNumbers(int.from_bytes(blob[24 : 24 + cb_e], "big"), int.from_bytes(blob[24 + cb_e : 24 + cb_e + cb_m], "big")).public_key()

    def _enc(obj: dict[str, Any]) -> str:
        if pub is None:
            return json.dumps(obj)
        aes_key, iv = os.urandom(32), os.urandom(12)
        ct_tag = AESGCM(aes_key).encrypt(iv, json.dumps(obj).encode("utf-8"), None)
        return json.dumps({
            "encrypted_payload": base64.b64encode(ct_tag[:-16]).decode("utf-8"),
            "encrypted_aes_key": base64.b64encode(pub.encrypt(aes_key, padding.PKCS1v15())).decode("utf-8"),
            "iv": base64.b64encode(iv).decode("utf-8"),
            "tag": base64.b64encode(ct_tag[-16:]).decode("utf-8"),
        })

    req_b = _enc({"token": "CANARY_VOTE_TOKEN", "machine_public_key": "PEM", "attestation_certificates": [], "nonce": "n-req-1"})
    cast_b = _enc({"token": "CANARY_VOTE_TOKEN", "machine_public_key": "PEM", "content": "{}", "id_voto": "VOTE-0", "nonce": "n-cast-1", "signature": "sig"})
    return base64.b64encode(req_b.encode()).decode(), base64.b64encode(cast_b.encode()).decode()


def _check_mobile_static_public_pinning() -> tuple[bool, bool, bool]:
    """Verifica Static Public Key Pinning (VotaAI_SecureKey_2) e bloqueio de cleartext em aplicação no Mobile."""
    constants_ts = MOBILE_DIR / "src" / "services" / "vote" / "vote.crypto.constants.ts"
    vote_srv_ts = MOBILE_DIR / "src" / "services" / "vote" / "vote.service.ts"
    has_static_key = False
    if constants_ts.is_file():
        txt = constants_ts.read_text(encoding="utf-8")
        has_static_key = "SERVER_MOBILE_TPM_PUBLIC_KEY" in txt and "-----BEGIN PUBLIC KEY-----" in txt
    no_req_cleartext, no_resp_cleartext = False, False
    if vote_srv_ts.is_file():
        vtxt = vote_srv_ts.read_text(encoding="utf-8")
        no_req_cleartext = "ENCRYPTION_UNAVAILABLE_MESSAGE" in vtxt and "encryptPayloadForServer" in vtxt
        no_resp_cleartext = "UNENCRYPTED_RESPONSE_MESSAGE" in vtxt and "decryptResponseFromServer" in vtxt
    return has_static_key, no_req_cleartext, no_resp_cleartext


def executar_teste_mobile(
    burp_host: str, burp_port: int, burp_ca: Path, target_host: str, bridge: OriginHTTPSBridge, origin_pin: str,
    build_type: str, override_host: str | None, override_sha256: str | None,
) -> tuple[CheckResult, CheckResult]:
    javac_bin, java_bin = shutil.which("javac"), shutil.which("java")
    jars = _find_okhttp_jars()
    if not javac_bin or not java_bin or len(jars) < 3:
        err = CheckResult("C3A", "Mobile | Camada de Transporte (TLS / Certificate Pinning via Burp)", "FALHOU", "JDK ou JARs OkHttp do cache Gradle ausentes.")
        err_app = CheckResult("C3B", "Mobile | Camada de Aplicação (Static Public Key Pinning)", "FALHOU", "Não avaliado devido à ausência de JDK/OkHttp.")
        return err, err_app

    pin_host, pin1, pin2, gaps = _load_mobile_build_pins(build_type)
    if override_host is not None:
        pin_host = override_host
    if override_sha256 is not None:
        pin1 = override_sha256

    req_b64, cast_b64 = _build_mobile_bodies()
    cp = os.pathsep.join(str(j) for j in jars)
    base_url = f"https://{target_host}:{bridge.port}"

    with tempfile.TemporaryDirectory(prefix="votaai_burp_okhttp_") as tmp_s:
        tmp = Path(tmp_s)
        java_src = tmp / "OkHttpBurpProbe.java"
        java_src.write_text(_OKHTTP_PROBE_JAVA, encoding="utf-8")
        comp = subprocess.run([javac_bin, "-cp", cp, str(java_src)], cwd=str(tmp), capture_output=True, text=True, timeout=30)
        if comp.returncode != 0:
            err = CheckResult("C3A", "Mobile | Camada de Transporte (TLS / Certificate Pinning via Burp)", "FALHOU", f"Erro ao compilar probe OkHttp: {comp.stderr[:300]}")
            err_app = CheckResult("C3B", "Mobile | Camada de Aplicação (Static Public Key Pinning)", "FALHOU", "Não avaliado por falha de compilação do probe.")
            return err, err_app

        run_cp = f"{tmp}{os.pathsep}{cp}"
        idx0 = bridge.snapshot()
        res_real = subprocess.run(
            [java_bin, "-cp", run_cp, "OkHttpBurpProbe", "real", burp_host, str(burp_port), str(burp_ca), base_url, pin_host, pin1, pin2, req_b64, cast_b64],
            cwd=str(tmp), capture_output=True, text=True, timeout=45,
        )
        reqs_real = bridge.since(idx0)

        idx_diag = bridge.snapshot()
        res_diag = subprocess.run(
            [java_bin, "-cp", run_cp, "OkHttpBurpProbe", "diag", burp_host, str(burp_port), str(burp_ca), base_url, target_host, origin_pin, "", req_b64, cast_b64],
            cwd=str(tmp), capture_output=True, text=True, timeout=45,
        )
        reqs_diag = bridge.since(idx_diag)

    if res_real.returncode != 0:
        err = CheckResult("C3A", "Mobile | Camada de Transporte (TLS / Certificate Pinning via Burp)", "FALHOU", f"Erro ao rodar probe OkHttp (rc={res_real.returncode}).", [res_real.stderr[:300]])
        err_app = CheckResult("C3B", "Mobile | Camada de Aplicação (Static Public Key Pinning)", "FALHOU", "Não avaliado por erro no probe OkHttp.")
        return err, err_app

    real_items = json.loads((res_real.stdout or "[]").strip())
    diag_items = json.loads((res_diag.stdout or "[]").strip()) if res_diag.returncode == 0 else []

    tls_details = [
        "Escopo desta camada: abortar o handshake TLS via CertificatePinner/network_security_config diante da PortSwigger CA (trabalhos futuros).",
        *gaps,
    ]
    all_aborted = True
    for it in real_items:
        ep = urllib.parse.urlparse(it["url"]).path
        aborted = it["http_status"] == -1 and any(k in (it["err_class"] + it["err_msg"]).lower() for k in ("sslpeerunverified", "sslhandshake", "cert", "pin"))
        if not aborted:
            all_aborted = False
        tls_details.append(f"Fluxo [{it['flow']}] {it['method']} {ep}: {'BLOQUEADO' if aborted else 'ATRAVESSOU BURP'} | HTTP={it['http_status']} | eventos=[{it['events']}]")

    cleartext_resps = [r["path"] for r in reqs_real if r["resp_is_cleartext_json"]]
    tls_details.append(
        f"O que o Burp inspecionou na camada HTTP/TLS: {len(reqs_real)} requisição(ões) do build {build_type} "
        f"(rotas, métodos, status) e respostas JSON em claro em {cleartext_resps or 'nenhuma'}."
    )
    for d in diag_items:
        diag_ok = d["http_status"] == -1 and "SSLPeerUnverifiedException" in d["err_class"] and len(reqs_diag) == 0
        tls_details.append(f"Diagnóstico com TLS Pinning ativado ({target_host}): {'BLOQUEOU' if diag_ok else 'FALHOU'} | erro={d['err_class']} | reqs_origin={len(reqs_diag)} | eventos=[{d['events']}]")

    if all_aborted and len(reqs_real) == 0 and not gaps:
        c3a = CheckResult("C3A", "Mobile | Camada de Transporte (TLS / Certificate Pinning via Burp)", "PASSOU", "Cliente móvel abortou TLS nos 3 fluxos e 0 requisições atravessaram o Burp.", tls_details)
    else:
        c3a = CheckResult("C3A", "Mobile | Camada de Transporte (TLS / Certificate Pinning via Burp)", "FALHOU", f"Sem TLS Certificate Pinning ativo ({build_type}): aceitou PortSwigger CA e trafegou {len(reqs_real)} requisição(ões).", tls_details)

    # C3B — Camada de Aplicação (Static Public Key Pinning com SERVER_MOBILE_TPM_PUBLIC_KEY)
    has_static_key, no_req_cleartext, no_resp_cleartext = _check_mobile_static_public_pinning()
    sensitive_posts = [r for r in reqs_real if r["method"] == "POST" and r["path"] in ("/api/vote/request/", "/api/vote/cast/")]
    hybrid_posts = [r for r in sensitive_posts if r["is_hybrid_envelope"]]
    plain_leaks = [(r["path"], r["body_plaintext_leaks"]) for r in sensitive_posts if r["body_plaintext_leaks"]]
    public_gets = [r for r in reqs_real if r["method"] == "GET"]

    app_details = [
        "Escopo desta camada: chave pública RSA estática do servidor (VotaAI_SecureKey_2 / SERVER_MOBILE_TPM_PUBLIC_KEY) embutida no app com envelope AES-256-GCM + RSA.",
        f"Estático: SERVER_MOBILE_TPM_PUBLIC_KEY={'presente' if has_static_key else 'AUSENTE'}, aborta sem cifragem={'sim' if no_req_cleartext else 'não'}, rejeita resposta 2xx em claro={'sim' if no_resp_cleartext else 'não'}.",
    ]
    if sensitive_posts:
        app_details.append(
            f"Dinâmico no payload pós-Burp: {len(hybrid_posts)}/{len(sensitive_posts)} POSTs sensíveis (/vote/request/, /vote/cast/) "
            f"em envelope híbrido | canários em claro no corpo: {len(plain_leaks)}."
        )
    else:
        app_details.append("Dinâmico: 0 POSTs sensíveis alcançaram o Origin (canal bloqueado na camada TLS).")
    if public_gets:
        app_details.append(
            f"Contraste rota pública: GET {', '.join(r['path'] for r in public_gets)} trafegou sem envelope de aplicação "
            f"(resp_cleartext_json={any(r['resp_is_cleartext_json'] for r in public_gets)})."
        )
    app_details.extend([
        "O que PROTEGE mesmo com TLS interceptado: token de votação, atestação StrongBox, chave do dispositivo e cédula de voto (ilegíveis ao Burp).",
        "O que NÃO PROTEGE sem Certificate Pinning: conexão TLS, endpoints/metadados e consultas públicas GET em texto claro.",
    ])

    c3b_ok = has_static_key and no_req_cleartext and no_resp_cleartext and (len(hybrid_posts) == len(sensitive_posts)) and (len(plain_leaks) == 0)
    c3b = CheckResult(
        "C3B",
        "Mobile | Camada de Aplicação (Static Public Key Pinning)",
        "PASSOU" if c3b_ok else "FALHOU",
        (
            f"Static Public Key Pinning protegeu {len(hybrid_posts)}/{len(sensitive_posts)} fluxos sensíveis de voto em envelope AES-GCM+RSA (0 vazamentos de corpo)."
            if c3b_ok
            else f"Falha na proteção de camada de aplicação (static_key={has_static_key}, plain_leaks={plain_leaks})."
        ),
        app_details,
    )
    return c3a, c3b


# ==============================================================================
# CLI e Execução Principal
# ==============================================================================
def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Teste 1 (Eixo 2): Resistência a MitM via Burp Suite real.")
    p.add_argument("--burp-proxy", default=DEFAULT_BURP_PROXY, help=f"Proxy Burp Suite (padrão: {DEFAULT_BURP_PROXY}).")
    p.add_argument("--burp-ca", type=Path, default=DEFAULT_BURP_CA, help=f"Certificado CA do Burp (padrão: {DEFAULT_BURP_CA}).")
    p.add_argument("--backend-url", default=DEFAULT_BACKEND_URL, help=f"Backend VotaAí local (padrão: {DEFAULT_BACKEND_URL}).")
    p.add_argument("--target", choices=("all", "desktop", "mobile"), default="all", help="Clientes a testar (padrão: all).")
    p.add_argument("--target-host", default=DEFAULT_TARGET_HOST, help=f"Hostname alvo HTTPS (padrão: {DEFAULT_TARGET_HOST}).")
    p.add_argument("--mobile-build-type", choices=("release", "debug"), default="release", help="BuildConfig do Android (padrão: release).")
    p.add_argument("--mobile-pin-host", default=None, help="Sobrescreve SSL_PINNING_HOST no probe OkHttp.")
    p.add_argument("--mobile-pin-sha256", default=None, help="Sobrescreve SSL_PINNING_SHA256 no probe OkHttp.")
    p.add_argument("--origin-port", type=int, default=0, help="Porta do Origin HTTPS local (padrão: 0 = efêmera; 8443 em --serve-https-only).")
    p.add_argument("--serve-https-only", action="store_true", help="Mantém apenas o Origin HTTPS ativo para testes manuais na GUI via Burp.")
    p.add_argument("--json-out", type=Path, default=None, help="Grava relatório JSON neste arquivo.")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    burp_host, _, burp_port_s = args.burp_proxy.partition(":")
    burp_host = burp_host.strip() or "127.0.0.1"
    burp_port = int(burp_port_s) if burp_port_s else 8080

    with tempfile.TemporaryDirectory(prefix="votaai_burp_eixo2_") as tmp_s:
        cert_path, key_path, origin_pin = gerar_cert_origin(Path(tmp_s), args.target_host)
        listen_port = args.origin_port or (8443 if args.serve_https_only else 0)
        bridge = OriginHTTPSBridge(cert_path, key_path, args.backend_url, host="0.0.0.0" if args.serve_https_only else "127.0.0.1", port=listen_port)
        try:
            if args.serve_https_only:
                print(f"Origin HTTPS ativo: https://{args.target_host}:{bridge.port} -> {args.backend_url} | SPKI={origin_pin}")
                print(f"Configure o cliente para proxy {burp_host}:{burp_port} e aponte API_BASE_URL para https://{args.target_host}:{bridge.port}. Ctrl+C para sair.")
                while True:
                    time.sleep(1.0)

            checks: list[CheckResult] = []
            c0, resolved_ca = verificar_ambiente_burp(burp_host, burp_port, args.burp_ca)
            checks.append(c0)
            if c0.status == "FALHOU" or resolved_ca is None:
                for chk in checks:
                    print(f"[{chk.status:<6}] {chk.code} - {chk.title}: {chk.summary}")
                    for line in chk.details:
                        print(f"           {line}")
                return 2

            checks.append(executar_controle_burp(burp_host, burp_port, args.target_host, bridge, origin_pin))
            tls_checks: list[CheckResult] = []
            app_checks: list[CheckResult] = []
            if args.target in ("all", "desktop"):
                c2a, c2b = executar_teste_desktop(burp_host, burp_port, args.target_host, bridge, DESKTOP_VENV_PYTHON)
                checks.extend([c2a, c2b])
                tls_checks.append(c2a)
                app_checks.append(c2b)
            if args.target in ("all", "mobile"):
                c3a, c3b = executar_teste_mobile(burp_host, burp_port, resolved_ca, args.target_host, bridge, origin_pin, args.mobile_build_type, args.mobile_pin_host, args.mobile_pin_sha256)
                checks.extend([c3a, c3b])
                tls_checks.append(c3a)
                app_checks.append(c3b)

            print("\n" + "=" * 78)
            print("ENSAIO DE REDE E COMUNICAÇÃO — MITM VIA BURP SUITE (EIXO 2 - TESTE 1)")
            print("=" * 78)
            print(f"Burp Proxy  : {burp_host}:{burp_port} (CA={resolved_ca})")
            print(f"Origin TLS  : https://{args.target_host}:{bridge.port} (SPKI={origin_pin})")
            print(f"Backend     : {args.backend_url}")
            print("-" * 78)
            for chk in checks:
                print(f"[{chk.status:<6}] {chk.code} - {chk.title}: {chk.summary}")
                for line in chk.details:
                    print(f"           {line}")
            print("-" * 78)

            tls_status = "APROVADO" if tls_checks and all(c.status == "PASSOU" for c in tls_checks) else "REPROVADO (trabalhos futuros)"
            app_status = "APROVADO (corpo sensível ilegível ao Burp)" if app_checks and all(c.status == "PASSOU" for c in app_checks) else "REPROVADO"
            verdict = "REPROVADO" if any(c.status == "FALHOU" for c in checks) else "APROVADO"
            print("RESUMO COMPARATIVO POR CAMADA:")
            print(f"  - Camada de Transporte (TLS / Certificate Pinning)     : {tls_status}")
            print(f"  - Camada de Aplicação  (Static Public Key Pinning)     : {app_status}")
            print("=" * 78)
            print(f"Resultado (critério estrito Cap. 3 — exige aborto TLS): {verdict}")
            if args.json_out:
                args.json_out.parent.mkdir(parents=True, exist_ok=True)
                args.json_out.write_text(
                    json.dumps(
                        {
                            "verdict": verdict,
                            "layer_summary": {"transport_tls_pinning": tls_status, "application_static_pubkey_pinning": app_status},
                            "checks": [asdict(c) for c in checks],
                            "origin_requests": bridge.requests,
                        },
                        indent=2,
                        ensure_ascii=False,
                    ),
                    encoding="utf-8",
                )
                print(f"Relatório JSON salvo em: {args.json_out}")
            return 0 if verdict == "APROVADO" else 1
        except KeyboardInterrupt:
            return 0
        finally:
            bridge.close()


if __name__ == "__main__":
    raise SystemExit(main())
