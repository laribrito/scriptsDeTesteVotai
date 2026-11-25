"""
Teste 2: Sigilo do Voto na API e no Banco de Dados (Eixo 1)

Submete opcionalmente sucessivos votos legítimos via API (/api/vote/request/ e
/api/vote/cast/) e executa uma auditoria direta via consultas SQL no banco de
dados relacional (PostgreSQL ou SQLite) e nos endpoints públicos da API para
tentar reconstruir qualquer vínculo direto, relacional, temporal ou estocástico
entre o eleitor registrado e a cédula depositada.
"""

from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import io
import json
import math
import os
import re
import sqlite3
import struct
import sys
import time
import uuid
import zipfile
from dataclasses import dataclass, field
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
    import psycopg2.extras
except ImportError:  # pragma: no cover - opcional quando usando apenas SQLite
    psycopg2 = None  # type: ignore[assignment]

# ==============================================================================
# Configuração padrão do ensaio
# ==============================================================================
DEFAULT_BASE_URL = "http://127.0.0.1:8000"
BACKEND_DIR = Path("/home/debrito/Programação/votaai-backend")
SE_KEYS_PATH = BACKEND_DIR / "se_keys_info.json"
DEFAULT_ENV_PATH = BACKEND_DIR / ".env"
DEFAULT_SQLITE_PATH = BACKEND_DIR / "db.sqlite3"
DEFAULT_DELAY_MS = 300
DEFAULT_WINDOW_MS = 5000.0
MIN_SAMPLE_STOCHASTIC = 5

IDENTITY_COLUMNS = {
    "voter_id",
    "user_id",
    "token_id",
    "token_hash",
    "email",
    "full_name",
    "nickname",
    "cpf",
    "ip",
    "used_ip",
    "machine_public_key",
    "nonce",
    "voter",
}
TIMESTAMP_COLUMN_NAMES = {
    "created_at",
    "updated_at",
    "used_at",
    "voted_at",
    "deposited_at",
    "timestamp",
}
SENSITIVE_FK_TABLES = {
    "Domain_electoralcollege",
    "Domain_votingtoken",
    "Domain_user",
}


# ==============================================================================
# Estruturas de dados do ensaio
# ==============================================================================
@dataclass
class SubmittedVote:
    raw_token: str
    token_hash: str
    election_id: int
    voter_id: int | None
    voter_name: str
    voter_email: str
    id_voto: str
    pacote_cifrado: str
    content: str
    choices: dict[str, int]
    choice_labels: dict[str, str]
    requested_at: datetime.datetime
    cast_at: datetime.datetime
    cast_response: dict[str, Any]
    machine_public_key: str


@dataclass
class CheckResult:
    code: str
    title: str
    status: str  # "PASSOU" | "FALHOU" | "ALERTA" | "N/A"
    summary: str
    details: list[str] = field(default_factory=list)


# ==============================================================================
# Camada Criptográfica e Submissão Legítima (3 camadas do Vota-i 2.0)
# ==============================================================================
def carregar_chave_api(se_keys_path: Path = SE_KEYS_PATH) -> rsa.RSAPublicKey:
    """Lê VotaAI_SecureKey_2 do arquivo se_keys_info.json e reconstrói a chave RSA."""
    keys = json.loads(se_keys_path.read_text(encoding="utf-8"))
    entry = next(k for k in keys if k["KeyName"] == "VotaAI_SecureKey_2")
    blob = base64.b64decode(entry["PublicKeyBase64"])
    _, _, cb_exp, cb_mod, _, _ = struct.unpack("<IIIIII", blob[:24])
    e = int.from_bytes(blob[24 : 24 + cb_exp], "big")
    n = int.from_bytes(blob[24 + cb_exp : 24 + cb_exp + cb_mod], "big")
    return rsa.RSAPublicNumbers(e, n).public_key()


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


def cifrar_envelope(pub_key: rsa.RSAPublicKey, payload: dict[str, Any]) -> dict[str, str]:
    """Cifra um dicionário no formato de envelope híbrido AES-256-GCM + RSA PKCS#1 v1.5."""
    aes_key, iv = os.urandom(32), os.urandom(12)
    ct_tag = AESGCM(aes_key).encrypt(iv, json.dumps(payload).encode("utf-8"), None)
    return {
        "encrypted_payload": base64.b64encode(ct_tag[:-16]).decode("utf-8"),
        "encrypted_aes_key": base64.b64encode(pub_key.encrypt(aes_key, padding.PKCS1v15())).decode("utf-8"),
        "iv": base64.b64encode(iv).decode("utf-8"),
        "tag": base64.b64encode(ct_tag[-16:]).decode("utf-8"),
    }


def decifrar_envelope_dict(priv_key: rsa.RSAPrivateKey, data: dict[str, Any]) -> Any:
    """Descriptografa um envelope híbrido AES-256-GCM + RSA PKCS#1 v1.5."""
    aes_key = priv_key.decrypt(base64.b64decode(data["encrypted_aes_key"]), padding.PKCS1v15())
    plain = AESGCM(aes_key).decrypt(
        base64.b64decode(data["iv"]),
        base64.b64decode(data["encrypted_payload"]) + base64.b64decode(data["tag"]),
        None,
    )
    return json.loads(plain.decode("utf-8"))


def decifrar_resposta(dev_priv: rsa.RSAPrivateKey, raw_text: str) -> Any:
    """Descriptografa resposta da API caso venha encapsulada em envelope híbrido."""
    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError:
        return raw_text
    if isinstance(data, dict) and {"encrypted_payload", "encrypted_aes_key", "iv", "tag"} <= data.keys():
        return decifrar_envelope_dict(dev_priv, data)
    return data


def decifrar_cedula(election_priv: rsa.RSAPrivateKey, content_str: str) -> dict[str, Any] | None:
    """Decifra uma cédula da urna usando a chave privada da eleição (RSA direto ou híbrido)."""
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

    try:
        cipher_bytes = base64.b64decode(pacote)
        plain = election_priv.decrypt(cipher_bytes, padding.PKCS1v15())
        parsed = json.loads(plain.decode("utf-8"))
        return parsed if isinstance(parsed, dict) else {"value": parsed}
    except Exception:
        return None


def _selecionar_opcoes_cedula(questions: list[dict[str, Any]], choice_index: int) -> tuple[dict[str, int], dict[str, str]]:
    """Seleciona opções rotacionadas por índice para distinguir votos no ground truth."""
    choices: dict[str, int] = {}
    choice_labels: dict[str, str] = {}
    for q in questions:
        options = q.get("options", [])
        if not options:
            continue
        non_blank = [opt for opt in options if opt.get("label") not in ("Branco", "Nulo")]
        pool = non_blank or options
        selected = pool[choice_index % len(pool)]
        choices[str(q["id"])] = selected["id"]
        choice_labels[str(q["id"])] = str(selected.get("label") or selected["id"])
    return choices, choice_labels


def submeter_voto_legitimo(
    base_url: str,
    api_pub: rsa.RSAPublicKey,
    raw_token: str,
    choice_index: int,
) -> SubmittedVote:
    """Executa o fluxo completo /api/vote/request/ -> /api/vote/cast/ para um eleitor."""
    dev_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    dev_pub_pem = dev_priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    nonce_req = f"nonce-req-{uuid.uuid4().hex[:12]}"
    req_envelope = cifrar_envelope(
        api_pub,
        {
            "token": raw_token,
            "machine_public_key": dev_pub_pem,
            "attestation_certificates": [gerar_certificado_strongbox(dev_priv, nonce_req)],
            "nonce": nonce_req,
        },
    )
    requested_at = datetime.datetime.now(datetime.timezone.utc)
    resp_req = requests.post(f"{base_url.rstrip('/')}/api/vote/request/", json=req_envelope, timeout=15)
    body_req = decifrar_resposta(dev_priv, resp_req.text)
    if resp_req.status_code != 200 or not isinstance(body_req, dict):
        raise RuntimeError(f"Erro em /api/vote/request/ (HTTP {resp_req.status_code}): {body_req}")

    id_voto = body_req["id_voto"]
    election = body_req["election"]
    voter = body_req.get("voter") or {}
    election_pub = serialization.load_pem_public_key(election["public_key"].encode("utf-8"))
    if not isinstance(election_pub, rsa.RSAPublicKey):
        raise RuntimeError("Chave pública da eleição não é RSA.")

    choices, choice_labels = _selecionar_opcoes_cedula(election.get("questions", []), choice_index)
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

    nonce_cast = f"nonce-cast-{uuid.uuid4().hex[:12]}"
    cast_envelope = cifrar_envelope(
        api_pub,
        {
            "token": raw_token,
            "machine_public_key": dev_pub_pem,
            "content": content,
            "id_voto": id_voto,
            "nonce": nonce_cast,
            "signature": signature,
        },
    )
    resp_cast = requests.post(f"{base_url.rstrip('/')}/api/vote/cast/", json=cast_envelope, timeout=15)
    cast_at = datetime.datetime.now(datetime.timezone.utc)
    body_cast = decifrar_resposta(dev_priv, resp_cast.text)
    if resp_cast.status_code != 200 or not isinstance(body_cast, dict) or body_cast.get("status") != "CONFIRMED":
        raise RuntimeError(f"Erro em /api/vote/cast/ (HTTP {resp_cast.status_code}): {body_cast}")

    token_hash = hashlib.sha256(raw_token.strip().encode("utf-8")).hexdigest()
    return SubmittedVote(
        raw_token=raw_token,
        token_hash=token_hash,
        election_id=int(election["id"]),
        voter_id=int(voter["id"]) if voter.get("id") is not None else None,
        voter_name=str(voter.get("full_name") or ""),
        voter_email=str(voter.get("email") or ""),
        id_voto=id_voto,
        pacote_cifrado=pacote_cifrado,
        content=content,
        choices=choices,
        choice_labels=choice_labels,
        requested_at=requested_at,
        cast_at=cast_at,
        cast_response=body_cast,
        machine_public_key=dev_pub_pem,
    )


# ==============================================================================
# Adaptador de Banco de Dados (PostgreSQL e SQLite)
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

    def get_columns(self, table_name: str) -> list[dict[str, Any]]:
        if not self.table_exists(table_name):
            return []
        if self.backend == "postgresql":
            pk_rows = self.query_all(
                """
                SELECT kcu.column_name
                FROM information_schema.table_constraints tc
                JOIN information_schema.key_column_usage kcu
                  ON tc.constraint_name = kcu.constraint_name
                 AND tc.table_schema = kcu.table_schema
                WHERE tc.table_schema = 'public'
                  AND tc.table_name = %s
                  AND tc.constraint_type = 'PRIMARY KEY'
                """,
                (table_name,),
            )
            pks = {r["column_name"] for r in pk_rows}
            col_rows = self.query_all(
                """
                SELECT column_name, data_type
                FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name = %s
                ORDER BY ordinal_position
                """,
                (table_name,),
            )
            return [
                {
                    "name": r["column_name"],
                    "data_type": r["data_type"],
                    "is_pk": r["column_name"] in pks,
                }
                for r in col_rows
            ]

        rows = self.query_all(f'PRAGMA table_info("{table_name}")')
        return [
            {
                "name": r["name"],
                "data_type": r["type"],
                "is_pk": bool(r["pk"]),
            }
            for r in rows
        ]

    def get_foreign_keys(self, table_name: str) -> list[dict[str, str]]:
        if not self.table_exists(table_name):
            return []
        if self.backend == "postgresql":
            rows = self.query_all(
                """
                SELECT kcu.column_name,
                       ccu.table_name AS foreign_table_name,
                       ccu.column_name AS foreign_column_name
                FROM information_schema.table_constraints tc
                JOIN information_schema.key_column_usage kcu
                  ON tc.constraint_name = kcu.constraint_name
                 AND tc.table_schema = kcu.table_schema
                JOIN information_schema.constraint_column_usage ccu
                  ON ccu.constraint_name = tc.constraint_name
                 AND ccu.table_schema = tc.table_schema
                WHERE tc.constraint_type = 'FOREIGN KEY'
                  AND tc.table_schema = 'public'
                  AND tc.table_name = %s
                """,
                (table_name,),
            )
            return [
                {
                    "column": r["column_name"],
                    "ref_table": r["foreign_table_name"],
                    "ref_column": r["foreign_column_name"],
                }
                for r in rows
            ]

        rows = self.query_all(f'PRAGMA foreign_key_list("{table_name}")')
        return [
            {
                "column": r["from"],
                "ref_table": r["table"],
                "ref_column": r["to"],
            }
            for r in rows
        ]


# ==============================================================================
# Utilitários Temporais e Estatísticos (Python puro)
# ==============================================================================
def parse_dt(val: Any) -> datetime.datetime | None:
    """Converte datetime ou string ISO-8601 (SQLite/PostgreSQL/API) para UTC aware."""
    if val is None or val == "":
        return None
    if isinstance(val, datetime.datetime):
        return val if val.tzinfo is not None else val.replace(tzinfo=datetime.timezone.utc)
    if isinstance(val, str):
        norm = val.strip().replace("Z", "+00:00")
        try:
            dt = datetime.datetime.fromisoformat(norm)
            return dt if dt.tzinfo is not None else dt.replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            return None
    return None


def _is_uuidv4(val: Any) -> bool:
    """Verifica se o valor representa um UUID versão 4 válido (não ordenável)."""
    try:
        return uuid.UUID(str(val)).version == 4
    except Exception:
        return False


def _average_ranks(values: list[float]) -> list[float]:
    n = len(values)
    indexed = sorted(enumerate(values), key=lambda item: item[1])
    ranks = [0.0] * n
    i = 0
    while i < n:
        j = i + 1
        while j < n and indexed[j][1] == indexed[i][1]:
            j += 1
        avg_rank = (i + 1 + j) / 2.0
        for k in range(i, j):
            ranks[indexed[k][0]] = avg_rank
        i = j
    return ranks


def spearman_rho(xs: list[float], ys: list[float]) -> float | None:
    """Calcula a correlação de postos de Spearman com tratamento de empates."""
    if len(xs) != len(ys) or len(xs) < 2:
        return None
    rx = _average_ranks(xs)
    ry = _average_ranks(ys)
    mx = sum(rx) / len(rx)
    my = sum(ry) / len(ry)
    num = sum((a - mx) * (b - my) for a, b in zip(rx, ry))
    den_x = math.sqrt(sum((a - mx) ** 2 for a in rx))
    den_y = math.sqrt(sum((b - my) ** 2 for b in ry))
    if den_x == 0.0 or den_y == 0.0:
        return None
    return num / (den_x * den_y)


def kendall_tau(xs: list[float], ys: list[float]) -> float | None:
    """Calcula o coeficiente tau-b de Kendall em Python puro."""
    n = len(xs)
    if n != len(ys) or n < 2:
        return None
    concordant = 0
    discordant = 0
    ties_x = 0
    ties_y = 0
    for i in range(n):
        for j in range(i + 1, n):
            dx = xs[i] - xs[j]
            dy = ys[i] - ys[j]
            if dx == 0 and dy == 0:
                ties_x += 1
                ties_y += 1
            elif dx == 0:
                ties_x += 1
            elif dy == 0:
                ties_y += 1
            elif (dx > 0 and dy > 0) or (dx < 0 and dy < 0):
                concordant += 1
            else:
                discordant += 1
    n0 = n * (n - 1) // 2
    denom = math.sqrt((n0 - ties_x) * (n0 - ties_y))
    if denom == 0.0:
        return None
    return (concordant - discordant) / denom


def permutation_exact_match_prob(n: int) -> float:
    """Probabilidade sob hipótese nula de acertar todas as N posições ao acaso (1 / N!)."""
    return 1.0 / math.factorial(n) if n >= 1 else 1.0


def extract_id_voto_from_content(content: str) -> str | None:
    """Extrai o identificador id_voto embutido no campo content da cédula."""
    try:
        parsed = json.loads(content)
        if isinstance(parsed, dict) and parsed.get("id_voto"):
            return str(parsed["id_voto"]).strip()
    except json.JSONDecodeError:
        pass
    m = re.search(r"VOTE-[0-9A-Fa-f]{32}", content)
    return m.group(0) if m else None


def pareamento_temporal_guloso(
    voters_ts: list[tuple[dict[str, Any], datetime.datetime]],
    ballots_ts: list[tuple[dict[str, Any], datetime.datetime]],
    window_ms: float,
) -> list[dict[str, Any]]:
    """Emparelhamento 1-para-1 guloso pelo menor |delta_ms| dentro da janela."""
    candidates: list[tuple[float, float, int, int]] = []
    for vi, (_, vt_dt) in enumerate(voters_ts):
        for bi, (_, bt_dt) in enumerate(ballots_ts):
            signed_ms = (bt_dt - vt_dt).total_seconds() * 1000.0
            abs_ms = abs(signed_ms)
            if abs_ms <= window_ms:
                candidates.append((abs_ms, signed_ms, vi, bi))
    candidates.sort(key=lambda item: item[0])

    used_v: set[int] = set()
    used_b: set[int] = set()
    matches: list[dict[str, Any]] = []
    for abs_ms, signed_ms, vi, bi in candidates:
        if vi in used_v or bi in used_b:
            continue
        used_v.add(vi)
        used_b.add(bi)
        matches.append(
            {
                "voter": voters_ts[vi][0],
                "voter_dt": voters_ts[vi][1],
                "ballot": ballots_ts[bi][0],
                "ballot_dt": ballots_ts[bi][1],
                "abs_ms": abs_ms,
                "signed_ms": signed_ms,
            }
        )
    return matches


# ==============================================================================
# Auditorias SQL e de API (A1 - A6)
# ==============================================================================
def _ground_truth_by_id_voto(ground_truth: list[SubmittedVote]) -> dict[str, SubmittedVote]:
    return {item.id_voto: item for item in ground_truth}


def _ground_truth_by_voter_id(ground_truth: list[SubmittedVote]) -> dict[int, SubmittedVote]:
    return {item.voter_id: item for item in ground_truth if item.voter_id is not None}


def auditar_esquema_relacional(db: DBAdapter, ctx: dict[str, Any]) -> CheckResult:
    """A1: Inspeciona FKs, colunas de PII e timestamps nas tabelas da urna."""
    vote_cols = db.get_columns("Domain_vote")
    ticket_cols = db.get_columns("Domain_ballotticket")
    ec_cols = db.get_columns("Domain_electoralcollege")
    vt_cols = db.get_columns("Domain_votingtoken")

    ctx["cols"] = {
        "Domain_vote": {c["name"]: c for c in vote_cols},
        "Domain_ballotticket": {c["name"]: c for c in ticket_cols},
        "Domain_electoralcollege": {c["name"]: c for c in ec_cols},
        "Domain_votingtoken": {c["name"]: c for c in vt_cols},
    }

    failures: list[str] = []
    details: list[str] = []

    for tbl in ("Domain_vote", "Domain_ballotticket"):
        if not db.table_exists(tbl):
            continue
        fks = db.get_foreign_keys(tbl)
        fk_desc = ", ".join(f"{fk['column']}->{fk['ref_table']}.{fk['ref_column']}" for fk in fks) or "nenhuma"
        details.append(f"FKs em {tbl}: {fk_desc}")
        for fk in fks:
            if fk["ref_table"] in SENSITIVE_FK_TABLES:
                failures.append(f"FK proibida em {tbl}.{fk['column']} -> {fk['ref_table']}")

        cols = db.get_columns(tbl)
        for col in cols:
            cname = col["name"].lower()
            if cname in IDENTITY_COLUMNS or any(k in cname for k in ("voter", "email", "user_id", "token")):
                failures.append(f"Coluna de identidade/PII em {tbl}: {col['name']}")

    vote_ts_cols = [
        c["name"]
        for c in vote_cols
        if c["name"].lower() in TIMESTAMP_COLUMN_NAMES
        or any(t in c["data_type"].lower() for t in ("timestamp", "date", "time"))
    ]
    if vote_ts_cols:
        failures.append(f"Coluna(s) de timestamp diretamente em Domain_vote: {', '.join(vote_ts_cols)}")
    else:
        details.append("Domain_vote sem colunas de timestamp.")

    ticket_ts_cols = [
        c["name"]
        for c in ticket_cols
        if c["name"].lower() in TIMESTAMP_COLUMN_NAMES
        or any(t in c["data_type"].lower() for t in ("timestamp", "date", "time"))
    ]
    if ticket_ts_cols:
        failures.append(f"Coluna(s) de timestamp em Domain_ballotticket: {', '.join(ticket_ts_cols)}")
    else:
        details.append("Domain_ballotticket sem colunas de timestamp.")

    vt_forbidden_cols = [
        c["name"]
        for c in vt_cols
        if c["name"].lower() in {"used_at", "used_ip", "created_at", "updated_at"}
    ]
    if vt_forbidden_cols:
        failures.append(
            f"Coluna(s) de data/IP proibida(s) em Domain_votingtoken: {', '.join(vt_forbidden_cols)}"
        )
    else:
        details.append("Domain_votingtoken sem created_at/updated_at/used_at/used_ip.")

    pk_summary = []
    for tbl, cols in (
        ("Domain_vote", vote_cols),
        ("Domain_ballotticket", ticket_cols),
        ("Domain_votingtoken", vt_cols),
    ):
        pk_col = next((c for c in cols if c["name"] == "id"), None)
        if pk_col:
            pk_summary.append(f"{tbl}.id={pk_col['data_type']}")
    if pk_summary:
        details.append(f"Chaves primárias: {', '.join(pk_summary)}")

    if "voted_at" in {c["name"] for c in ec_cols}:
        details.append("Timestamp permitido em quórum: Domain_electoralcollege(voted_at)")

    if failures:
        return CheckResult(
            code="A1",
            title="Esquema Relacional, FKs e Colunas da Urna",
            status="FALHOU",
            summary=f"{len(failures)} violação(ões) estrutural(is) detectada(s) no esquema.",
            details=failures + details,
        )
    return CheckResult(
        code="A1",
        title="Esquema Relacional, FKs e Colunas da Urna",
        status="PASSOU",
        summary="Nenhuma FK, PII ou timestamp correlacionável em Domain_vote, Domain_ballotticket ou Domain_votingtoken.",
        details=details,
    )


def auditar_conteudo_e_tickets(db: DBAdapter, election_id: int, ctx: dict[str, Any]) -> CheckResult:
    """A2: Verifica ausência de PII/plaintext em Domain_vote e inspeciona JOIN com BallotTicket."""
    voters = db.query_all(
        'SELECT id, full_name, email, nickname FROM "Domain_electoralcollege" WHERE election_id = %s',
        (election_id,),
    )
    tokens = db.query_all(
        'SELECT id, voter_id, token_hash, machine_public_key, nonce FROM "Domain_votingtoken" WHERE election_id = %s',
        (election_id,),
    )
    votes = db.query_all(
        'SELECT id, id_generated, content FROM "Domain_vote" WHERE election_id = %s ORDER BY id ASC',
        (election_id,),
    )

    failures: list[str] = []
    details: list[str] = [f"Votos analisados em Domain_vote: {len(votes)}"]

    pii_needles: list[tuple[str, str]] = []
    for v in voters:
        if v.get("email"):
            pii_needles.append((f"email({v['email']})", str(v["email"])))
        if v.get("full_name") and len(str(v["full_name"]).strip()) >= 4:
            pii_needles.append((f"nome({v['full_name']})", str(v["full_name"]).strip()))
    for t in tokens:
        if t.get("token_hash"):
            pii_needles.append(("token_hash", str(t["token_hash"])))
        if t.get("machine_public_key"):
            key_body = str(t["machine_public_key"]).replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").strip()
            if len(key_body) >= 32:
                pii_needles.append(("machine_public_key", key_body[:32]))

    for row in votes:
        haystack = f"{row['id_generated']}\n{row['content']}"
        for label, needle in pii_needles:
            if needle in haystack:
                failures.append(f"Vote #{row['id']} contém dado sensível '{label}'.")
        try:
            parsed = json.loads(row["content"])
            if isinstance(parsed, dict) and "choices" in parsed:
                failures.append(f"Vote #{row['id']} expõe 'choices' em texto plano em Domain_vote.content.")
        except json.JSONDecodeError:
            pass

    ticket_links: list[dict[str, Any]] = []
    if db.table_exists("Domain_ballotticket"):
        ticket_links = db.query_all(
            """
            SELECT v.id AS vote_id, v.id_generated, bt.id AS ticket_id, bt.id_voto, bt.is_used
            FROM "Domain_vote" v
            JOIN "Domain_ballotticket" bt
              ON bt.election_id = v.election_id
             AND v.content LIKE ('%%' || bt.id_voto || '%%')
            WHERE v.election_id = %s
            ORDER BY v.id ASC
            """,
            (election_id,),
        ) if db.backend == "postgresql" else db.query_all(
            """
            SELECT v.id AS vote_id, v.id_generated, bt.id AS ticket_id, bt.id_voto, bt.is_used
            FROM "Domain_vote" v
            JOIN "Domain_ballotticket" bt
              ON bt.election_id = v.election_id
             AND v.content LIKE ('%' || bt.id_voto || '%')
            WHERE v.election_id = %s
            ORDER BY v.id ASC
            """,
            (election_id,),
        )
        details.append(
            f"JOIN direto Domain_vote <-> Domain_ballotticket (via id_voto em content): "
            f"{len(ticket_links)}/{len(votes)} cédula(s) vinculada(s) a ticket."
        )
        if ticket_links:
            failures.append(
                f"Domain_vote.content expõe id_voto ligável diretamente a Domain_ballotticket ({len(ticket_links)} cédula(s))."
            )

    ctx["ticket_links"] = ticket_links
    ctx["votes"] = votes
    ctx["voters"] = voters
    ctx["tokens"] = tokens

    if failures:
        return CheckResult(
            code="A2",
            title="Conteúdo da Urna, Cifragem e Vínculo com Tickets",
            status="FALHOU",
            summary=failures[0],
            details=failures + details,
        )
    return CheckResult(
        code="A2",
        title="Conteúdo da Urna, Cifragem e Vínculo com Tickets",
        status="PASSOU",
        summary="Sem PII, escolhas em texto plano ou vínculo de id_voto em Domain_vote.",
        details=details,
    )


def auditar_correlacao_temporal(
    db: DBAdapter,
    election_id: int,
    window_ms: float,
    ground_truth: list[SubmittedVote],
    ctx: dict[str, Any],
) -> CheckResult:
    """A3: Tenta reconstruir vínculo eleitor/token <-> ticket/cédula via timestamps SQL."""
    ec_cols = ctx["cols"]["Domain_electoralcollege"]
    bt_cols = ctx["cols"]["Domain_ballotticket"]
    vt_cols = ctx["cols"]["Domain_votingtoken"]
    vote_cols = ctx["cols"]["Domain_vote"]

    gt_by_id_voto = _ground_truth_by_id_voto(ground_truth)
    gt_by_voter = _ground_truth_by_voter_id(ground_truth)

    findings: list[str] = []
    details: list[str] = []
    reconstructed_by_voter: dict[int, dict[str, Any]] = {}

    like_pattern = "('%%' || bt.id_voto || '%%')" if db.backend == "postgresql" else "('%' || bt.id_voto || '%')"

    # 1. JOIN SQL exato: ec.voted_at = bt.used_at -> v
    if "voted_at" in ec_cols and "used_at" in bt_cols and db.table_exists("Domain_ballotticket"):
        exact_rows = db.query_all(
            f"""
            SELECT ec.id AS voter_id, ec.full_name, ec.email, ec.voted_at,
                   bt.id AS ticket_id, bt.id_voto, bt.used_at,
                   v.id AS vote_id, v.id_generated, v.content
            FROM "Domain_electoralcollege" ec
            JOIN "Domain_ballotticket" bt
              ON bt.election_id = ec.election_id
             AND bt.used_at = ec.voted_at
            JOIN "Domain_vote" v
              ON v.election_id = bt.election_id
             AND v.content LIKE {like_pattern}
            WHERE ec.election_id = %s
              AND ec.has_voted = %s
              AND ec.voted_at IS NOT NULL
            ORDER BY ec.voted_at ASC
            """,
            (election_id, True),
        )
        if exact_rows:
            findings.append(
                f"JOIN SQL direto (ec.voted_at = bt.used_at -> v.content LIKE id_voto) reconstruiu "
                f"{len(exact_rows)} vínculo(s) exato(s) com delta = 0.000 ms!"
            )
            for row in exact_rows:
                reconstructed_by_voter[int(row["voter_id"])] = row
                gt_tag = ""
                if row["id_voto"] in gt_by_id_voto and int(row["voter_id"]) in gt_by_voter:
                    ok = gt_by_id_voto[row["id_voto"]].voter_id == int(row["voter_id"])
                    gt_tag = f" [GROUND TRUTH: {'MATCH EXATO' if ok else 'DIVERGENTE'}]"
                details.append(
                    f"  [EXATO 0.000 ms] {row['full_name']} <{row['email']}> (voted_at={row['voted_at']}) "
                    f"-> Ticket #{row['ticket_id']} ({row['id_voto']}) -> Vote #{row['vote_id']}{gt_tag}"
                )

    # 2. Proximidade temporal dentro de window_ms (ec.voted_at <-> bt.used_at)
    if "voted_at" in ec_cols and "used_at" in bt_cols and db.table_exists("Domain_ballotticket"):
        ec_rows = db.query_all(
            """
            SELECT id AS voter_id, full_name, email, voted_at
            FROM "Domain_electoralcollege"
            WHERE election_id = %s AND has_voted = %s AND voted_at IS NOT NULL
            ORDER BY voted_at ASC
            """,
            (election_id, True),
        )
        bt_rows = db.query_all(
            f"""
            SELECT bt.id AS ticket_id, bt.id_voto, bt.created_at, bt.used_at,
                   v.id AS vote_id, v.id_generated, v.content
            FROM "Domain_ballotticket" bt
            JOIN "Domain_vote" v
              ON v.election_id = bt.election_id
             AND v.content LIKE {like_pattern}
            WHERE bt.election_id = %s AND bt.used_at IS NOT NULL
            ORDER BY bt.used_at ASC
            """,
            (election_id,),
        )
        v_ts = [(r, dt) for r in ec_rows if (dt := parse_dt(r["voted_at"])) is not None]
        b_ts = [(r, dt) for r in bt_rows if (dt := parse_dt(r["used_at"])) is not None]
        prox_matches = pareamento_temporal_guloso(v_ts, b_ts, window_ms)
        near_only = [m for m in prox_matches if m["abs_ms"] > 0.0]
        if near_only:
            findings.append(
                f"Correlação por janela temporal (<= {window_ms:.0f} ms) entre ec.voted_at e bt.used_at "
                f"pareou {len(near_only)} vínculo(s) adicional(is)."
            )
            for m in near_only:
                v_row = m["voter"]
                b_row = m["ballot"]
                reconstructed_by_voter.setdefault(int(v_row["voter_id"]), {**v_row, **b_row})
                details.append(
                    f"  [JANELA {m['abs_ms']:.3f} ms] {v_row['full_name']} -> {b_row['id_voto']} -> Vote #{b_row['vote_id']}"
                )

    # 3. Auditoria de timestamps e IP em Domain_votingtoken (somente colunas existentes)
    optional_vt_cols = [
        c for c in ("used_at", "used_ip", "created_at", "updated_at", "last_attempt_at", "last_attempt_ip")
        if c in vt_cols
    ]
    select_vt_extra = (", " + ", ".join(f"vt.{c}" for c in optional_vt_cols)) if optional_vt_cols else ""
    vt_rows = db.query_all(
        f"""
        SELECT vt.id AS token_id, vt.voter_id, ec.full_name, ec.email,
               vt.is_used{select_vt_extra}
        FROM "Domain_votingtoken" vt
        JOIN "Domain_electoralcollege" ec ON ec.id = vt.voter_id
        WHERE vt.election_id = %s AND vt.is_used = %s
        ORDER BY vt.id ASC
        """,
        (election_id, True),
    )
    used_at_filled = [r for r in vt_rows if r.get("used_at") is not None]
    used_ip_filled = [r for r in vt_rows if r.get("used_ip")]
    last_attempt_filled = [r for r in vt_rows if r.get("last_attempt_at") is not None]
    if used_at_filled:
        findings.append(f"Domain_votingtoken.used_at preenchido em {len(used_at_filled)} token(s) consumido(s).")
    if used_ip_filled:
        findings.append(f"Domain_votingtoken.used_ip preenchido em {len(used_ip_filled)} token(s) consumido(s).")
    if last_attempt_filled:
        findings.append(f"Domain_votingtoken.last_attempt_at mantido após consumo em {len(last_attempt_filled)} token(s).")

    # Verifica se updated_at (quando != created_at), used_at ou last_attempt_at correlaciona com bt.created_at/bt.used_at
    if db.table_exists("Domain_ballotticket") and vt_rows and ("used_at" in bt_cols or "created_at" in bt_cols):
        bt_time_cols = [c for c in ("created_at", "used_at") if c in bt_cols]
        bt_select = ", ".join(f"bt.{c}" for c in bt_time_cols)
        tickets_all = db.query_all(
            f"""
            SELECT bt.id AS ticket_id, bt.id_voto, {bt_select},
                   v.id AS vote_id, v.id_generated
            FROM "Domain_ballotticket" bt
            LEFT JOIN "Domain_vote" v
              ON v.election_id = bt.election_id
             AND v.content LIKE {like_pattern}
            WHERE bt.election_id = %s
            """,
            (election_id,),
        )
        for col_name in ("used_at", "last_attempt_at", "updated_at"):
            if col_name not in vt_cols:
                continue
            vt_ts: list[tuple[dict[str, Any], datetime.datetime]] = []
            for r in vt_rows:
                dt = parse_dt(r.get(col_name))
                if dt is None:
                    continue
                if col_name == "updated_at" and parse_dt(r.get("created_at")) == dt:
                    continue
                vt_ts.append((r, dt))
            if not vt_ts:
                continue
            for bt_col in bt_time_cols:
                bt_ts = [(t, dt) for t in tickets_all if (dt := parse_dt(t.get(bt_col))) is not None]
                vt_matches = pareamento_temporal_guloso(vt_ts, bt_ts, window_ms)
                if vt_matches:
                    findings.append(
                        f"Domain_votingtoken.{col_name} correlaciona com Domain_ballotticket.{bt_col} "
                        f"(<= {window_ms:.0f} ms) em {len(vt_matches)} caso(s)."
                    )
                    for m in vt_matches[:10]:
                        details.append(
                            f"  [TOKEN {col_name} <-> {bt_col} {m['abs_ms']:.1f} ms] "
                            f"{m['voter']['full_name']} -> {m['ballot']['id_voto']} (Vote #{m['ballot'].get('vote_id')})"
                        )

    # 4. Se Domain_vote tiver qualquer coluna de timestamp diretamente, checar contra ec.voted_at
    direct_vote_ts_cols = [
        c["name"]
        for c in vote_cols.values()
        if c["name"].lower() in TIMESTAMP_COLUMN_NAMES
        or any(t in c["data_type"].lower() for t in ("timestamp", "date", "time"))
    ]
    if direct_vote_ts_cols and "voted_at" in ec_cols:
        ec_rows_v = db.query_all(
            'SELECT id AS voter_id, full_name, voted_at FROM "Domain_electoralcollege" '
            'WHERE election_id = %s AND has_voted = %s AND voted_at IS NOT NULL',
            (election_id, True),
        )
        v_ts_only = [(r, dt) for r in ec_rows_v if (dt := parse_dt(r["voted_at"])) is not None]
        for v_col in direct_vote_ts_cols:
            v_rows = db.query_all(
                f'SELECT id AS vote_id, id_generated, "{v_col}" AS ts FROM "Domain_vote" WHERE election_id = %s',
                (election_id,),
            )
            b_ts_only = [(r, dt) for r in v_rows if (dt := parse_dt(r["ts"])) is not None]
            direct_m = pareamento_temporal_guloso(v_ts_only, b_ts_only, window_ms)
            if direct_m:
                findings.append(
                    f"Correlação direta ec.voted_at <-> Domain_vote.{v_col} ligou {len(direct_m)} registro(s)."
                )

    if ground_truth and reconstructed_by_voter:
        confirmed = sum(
            1
            for vid, rec in reconstructed_by_voter.items()
            if vid in gt_by_voter and rec.get("id_voto") == gt_by_voter[vid].id_voto
        )
        details.append(
            f"Conferência contra ground truth submetido: {confirmed}/{len(ground_truth)} "
            f"votos reconstruídos corretamente por correlação temporal."
        )

    ctx["reconstructed_by_voter"] = reconstructed_by_voter

    if findings:
        return CheckResult(
            code="A3",
            title="Correlação Temporal (Timestamps) via SQL Direto",
            status="FALHOU",
            summary=findings[0],
            details=findings + details,
        )

    if "voted_at" not in ec_cols or not any(parse_dt(v.get("voted_at")) for v in ctx.get("voters_voted", [])):
        details.append("Nenhum carimbo temporal utilizável encontrado ligando eleitor/token a ticket/voto.")
    return CheckResult(
        code="A3",
        title="Correlação Temporal (Timestamps) via SQL Direto",
        status="PASSOU",
        summary="Nenhuma correlação temporal encontrada entre eleitor/token e cédula/ticket.",
        details=details,
    )


def auditar_correlacao_estocastica_ordem(
    db: DBAdapter,
    election_id: int,
    ground_truth: list[SubmittedVote],
    ctx: dict[str, Any],
) -> CheckResult:
    """A4: Valida PKs UUIDv4 não ordenáveis e avalia correlação estocástica (Spearman/Kendall)."""
    vote_pk_col = ctx["cols"]["Domain_vote"].get("id", {"data_type": "unknown"})
    pk_type = str(vote_pk_col.get("data_type", "")).lower()
    pk_declared_int = any(t in pk_type for t in ("int", "serial", "bigint", "integer"))

    votes = db.query_all(
        'SELECT id, id_generated, content FROM "Domain_vote" WHERE election_id = %s ORDER BY id ASC',
        (election_id,),
    )
    tickets = (
        db.query_all('SELECT id FROM "Domain_ballotticket" WHERE election_id = %s', (election_id,))
        if db.table_exists("Domain_ballotticket")
        else []
    )
    tokens_pks = db.query_all('SELECT id FROM "Domain_votingtoken" WHERE election_id = %s', (election_id,))

    ec_cols = ctx["cols"]["Domain_electoralcollege"]
    has_voted_at = "voted_at" in ec_cols

    voters_voted = db.query_all(
        f"""
        SELECT id AS voter_id, full_name, email{', voted_at' if has_voted_at else ''}
        FROM "Domain_electoralcollege"
        WHERE election_id = %s AND has_voted = %s
        ORDER BY {'voted_at ASC, id ASC' if has_voted_at else 'id ASC'}
        """,
        (election_id, True),
    )
    ctx["voters_voted"] = voters_voted

    vote_ids = [v["id"] for v in votes]
    vote_pk_all_uuidv4 = bool(vote_ids) and all(_is_uuidv4(vid) for vid in vote_ids)
    ticket_pk_all_uuidv4 = (not tickets) or all(_is_uuidv4(t["id"]) for t in tickets)
    token_pk_all_uuidv4 = (not tokens_pks) or all(_is_uuidv4(t["id"]) for t in tokens_pks)

    pk_failures: list[str] = []
    if pk_declared_int or (vote_ids and not vote_pk_all_uuidv4):
        pk_failures.append(f"Domain_vote.id não é UUIDv4 não ordenável (tipo='{vote_pk_col.get('data_type')}').")
    if not ticket_pk_all_uuidv4:
        pk_failures.append("Domain_ballotticket.id contém PK que não é UUIDv4.")
    if not token_pk_all_uuidv4:
        pk_failures.append("Domain_votingtoken.id contém PK que não é UUIDv4.")

    details: list[str] = [
        f"Tipo da PK Domain_vote.id: '{vote_pk_col.get('data_type')}' (UUIDv4={vote_pk_all_uuidv4}, sequencial_int={pk_declared_int}).",
        f"UUIDv4 em tabelas auxiliares: BallotTicket={ticket_pk_all_uuidv4} | VotingToken={token_pk_all_uuidv4}.",
        f"Eleitores que votaram: {len(voters_voted)} | Cédulas em Domain_vote: {len(votes)}.",
    ]
    if vote_ids:
        details.append(f"IDs de Domain_vote (ordenados por id ASC): {[str(vid) for vid in vote_ids]}")

    if pk_failures:
        return CheckResult(
            code="A4",
            title="IDs Primários UUIDv4 e Correlação Estocástica de Ordem",
            status="FALHOU",
            summary=pk_failures[0],
            details=pk_failures + details,
        )

    voters_with_ts = [v for v in voters_voted if parse_dt(v.get("voted_at")) is not None] if has_voted_at else []
    n_voters = len(voters_voted)
    n_votes = len(votes)
    reconstructed = ctx.get("reconstructed_by_voter", {})
    gt_by_voter = _ground_truth_by_voter_id(ground_truth)

    if n_votes < 2 or n_voters < 2:
        details.append(
            f"Amostra insuficiente (N={n_voters} votante(s), {n_votes} cédula(s)). "
            f"Submeta ao menos 2 votos (recomendado >= {MIN_SAMPLE_STOCHASTIC}) para validação estocástica."
        )
        return CheckResult(
            code="A4",
            title="IDs Primários UUIDv4 e Correlação Estocástica de Ordem",
            status="ALERTA",
            summary=f"Amostra insuficiente (N={n_voters} < 2); PKs são UUIDv4 válidos.",
            details=details,
        )

    # Verifica correlação estocástica apenas se houver associação verdadeira conhecida (A3 ou ground truth)
    ordered_voters = voters_with_ts if len(voters_with_ts) >= 2 else voters_voted
    vote_id_to_rank = {v["id"]: idx + 1 for idx, v in enumerate(votes)}
    voter_ranks: list[float] = []
    true_ranks: list[float] = []
    positional_hits = 0

    for idx, voter in enumerate(ordered_voters):
        vid = int(voter["voter_id"])
        true_vote_id = None
        if vid in reconstructed and reconstructed[vid].get("vote_id") is not None:
            true_vote_id = reconstructed[vid]["vote_id"]
        elif vid in gt_by_voter:
            gt_pacote = gt_by_voter[vid].pacote_cifrado
            gt_content = gt_by_voter[vid].content
            matched_v = next((vv for vv in votes if vv["content"] in (gt_pacote, gt_content)), None)
            if matched_v is not None:
                true_vote_id = matched_v["id"]

        if true_vote_id is not None and true_vote_id in vote_id_to_rank:
            voter_ranks.append(float(idx + 1))
            true_ranks.append(float(vote_id_to_rank[true_vote_id]))
            if idx < len(votes) and votes[idx]["id"] == true_vote_id:
                positional_hits += 1

    if len(voter_ranks) >= 2:
        rho = spearman_rho(voter_ranks, true_ranks)
        tau = kendall_tau(voter_ranks, true_ranks)
        p_chance = permutation_exact_match_prob(len(voter_ranks))
        details.append(
            f"Teste de ordem (N={len(voter_ranks)}): hits={positional_hits}/{len(voter_ranks)}, "
            f"Spearman rho={rho if rho is not None else 0.0:+.4f}, "
            f"Kendall tau={tau if tau is not None else 0.0:+.4f}, P(acaso 1/N!)={p_chance:.6g}."
        )
        if len(voter_ranks) >= MIN_SAMPLE_STOCHASTIC and rho is not None and rho >= 0.85:
            return CheckResult(
                code="A4",
                title="IDs Primários UUIDv4 e Correlação Estocástica de Ordem",
                status="FALHOU",
                summary=f"Evidência estatística de ordenação oculta (Spearman rho={rho:+.4f}, N={len(voter_ranks)}).",
                details=details,
            )
        if len(voter_ranks) < MIN_SAMPLE_STOCHASTIC:
            details.append(
                f"Nota: N={len(voter_ranks)} < {MIN_SAMPLE_STOCHASTIC}; para poder estatístico de permutação "
                f"(P(acaso) <= 1/120), recomenda-se submeter >= {MIN_SAMPLE_STOCHASTIC} votos sucessivos."
            )
    else:
        details.append(
            "Sem ground truth ou vínculo temporal para parear votos; PK UUIDv4 impede inferência ordinal a partir do banco."
        )
        if n_votes < MIN_SAMPLE_STOCHASTIC:
            details.append(
                f"Nota: N={n_votes} < {MIN_SAMPLE_STOCHASTIC}; para validação estocástica com ground truth, "
                f"recomenda-se submeter >= {MIN_SAMPLE_STOCHASTIC} votos sucessivos."
            )

    return CheckResult(
        code="A4",
        title="IDs Primários UUIDv4 e Correlação Estocástica de Ordem",
        status="PASSOU",
        summary="PKs UUIDv4 não ordenáveis em Domain_vote, Domain_ballotticket e Domain_votingtoken; ordem não correlaciona com voted_at.",
        details=details,
    )


def auditar_metadados_transacionais_pg(
    db: DBAdapter,
    election_id: int,
    election_status: str,
    ctx: dict[str, Any],
) -> CheckResult:
    """A5: No PostgreSQL, verifica acoplamento transacional via xmin (incluindo xmin+1 em CLOSED/TALLIED) e ctid."""
    if db.backend != "postgresql":
        return CheckResult(
            code="A5",
            title="Acoplamento Transacional e Metadados Físicos (PostgreSQL xmin/ctid)",
            status="N/A",
            summary="Inspeção MVCC (xmin/ctid) indisponível em SQLite; requer PostgreSQL.",
            details=[
                "SQLite não expõe ID de transação MVCC (xmin) nem tupla física (ctid).",
                "Configure DB_NAME no .env ou passe --db-url postgresql://... para executar A5.",
            ],
        )

    overlaps_ec_vote = db.query_all(
        """
        SELECT ec.id AS voter_id, ec.full_name, ec.email, ec.xmin::text AS ec_xmin,
               v.id AS vote_id, v.id_generated, v.xmin::text AS vote_xmin, v.ctid::text AS vote_ctid
        FROM "Domain_electoralcollege" ec
        JOIN "Domain_vote" v
          ON v.election_id = ec.election_id
         AND ec.xmin::text = v.xmin::text
        WHERE ec.election_id = %s
        ORDER BY v.id ASC
        """,
        (election_id,),
    )
    overlaps_vt_vote = db.query_all(
        """
        SELECT vt.id AS token_id, vt.voter_id, vt.xmin::text AS vt_xmin,
               v.id AS vote_id, v.id_generated, v.xmin::text AS vote_xmin
        FROM "Domain_votingtoken" vt
        JOIN "Domain_vote" v
          ON v.election_id = vt.election_id
         AND vt.xmin::text = v.xmin::text
        WHERE vt.election_id = %s
        ORDER BY v.id ASC
        """,
        (election_id,),
    )
    overlaps_ec_bt: list[dict[str, Any]] = []
    if db.table_exists("Domain_ballotticket"):
        overlaps_ec_bt = db.query_all(
            """
            SELECT ec.id AS voter_id, ec.full_name, ec.xmin::text AS ec_xmin,
                   bt.id AS ticket_id, bt.id_voto, bt.xmin::text AS bt_xmin
            FROM "Domain_electoralcollege" ec
            JOIN "Domain_ballotticket" bt
              ON bt.election_id = ec.election_id
             AND ec.xmin::text = bt.xmin::text
            WHERE ec.election_id = %s
            ORDER BY bt.id ASC
            """,
            (election_id,),
        )

    prox_ec_vote: list[dict[str, Any]] = []
    if election_status in ("CLOSED", "TALLIED"):
        prox_ec_vote = db.query_all(
            """
            SELECT ec.id AS voter_id, ec.full_name, ec.xmin::text AS ec_xmin,
                   v.id AS vote_id, v.xmin::text AS vote_xmin
            FROM "Domain_electoralcollege" ec
            JOIN "Domain_vote" v
              ON v.election_id = ec.election_id
             AND ABS(v.xmin::text::bigint - ec.xmin::text::bigint) <= 1
            WHERE ec.election_id = %s AND ec.has_voted = %s
            """,
            (election_id, True),
        )

    ctid_rows = db.query_all(
        """
        SELECT id AS vote_id, id_generated, ctid::text AS vote_ctid, xmin::text AS vote_xmin
        FROM "Domain_vote"
        WHERE election_id = %s
        ORDER BY ctid ASC
        """,
        (election_id,),
    )
    distinct_vote_xmin = sorted({str(r["vote_xmin"]) for r in ctid_rows})

    details: list[str] = [
        f"Sobreposições xmin (ElectoralCollege <-> Vote): {len(overlaps_ec_vote)}",
        f"Sobreposições xmin (VotingToken <-> Vote): {len(overlaps_vt_vote)}",
        f"Sobreposições xmin (ElectoralCollege <-> BallotTicket): {len(overlaps_ec_bt)}",
        f"Proximidade xmin (|v.xmin - ec.xmin| <= 1 em {election_status}): {len(prox_ec_vote)}",
        f"xmin distintos em Domain_vote: {distinct_vote_xmin}",
        f"Tuplas físicas ctid em Domain_vote: {[r['vote_ctid'] for r in ctid_rows]}",
    ]
    for ov in overlaps_ec_vote[:10]:
        details.append(
            f"  [MESMA TX xmin={ov['ec_xmin']}] {ov['full_name']} <{ov['email']}> "
            f"-> Vote #{ov['vote_id']} (ctid={ov['vote_ctid']})"
        )

    total_overlaps = len(overlaps_ec_vote) + len(overlaps_vt_vote) + len(overlaps_ec_bt) + len(prox_ec_vote)
    if total_overlaps > 0:
        return CheckResult(
            code="A5",
            title="Acoplamento Transacional e Metadados Físicos (PostgreSQL xmin/ctid)",
            status="FALHOU",
            summary=(
                f"Acoplamento transacional detectado no PostgreSQL "
                f"({total_overlaps} ocorrência(s) de xmin igual ou adjacente)."
            ),
            details=details,
        )

    return CheckResult(
        code="A5",
        title="Acoplamento Transacional e Metadados Físicos (PostgreSQL xmin/ctid)",
        status="PASSOU",
        summary="Nenhuma sobreposição ou adjacência de transaction ID (xmin) entre presença do eleitor e cédula.",
        details=details,
    )


def _inspecionar_ordem_zip_auditoria(base_url: str, election_id: int) -> tuple[list[str], list[str], list[str]]:
    """Baixa /audit-package/ em memória e verifica ordem e conteúdo das cédulas."""
    notes: list[str] = []
    findings: list[str] = []
    zip_ids: list[str] = []
    url = f"{base_url.rstrip('/')}/api/public/elections/{election_id}/audit-package/"
    resp = requests.get(url, timeout=15)
    if resp.status_code != 200:
        notes.append(f"GET /audit-package/ retornou HTTP {resp.status_code}.")
        return findings, notes, zip_ids

    with zipfile.ZipFile(io.BytesIO(resp.content), "r") as zf:
        names = zf.namelist()
        notes.append(f"ZIP audit-package contém: {', '.join(names)}")
        if "votos_criptografados.json" in names:
            zip_votes = json.loads(zf.read("votos_criptografados.json").decode("utf-8"))
            zip_ids = [str(v.get("id_generated")) for v in zip_votes if isinstance(v, dict) and v.get("id_generated")]
            leaked_in_zip = [
                v.get("id_generated")
                for v in zip_votes
                if isinstance(v, dict) and extract_id_voto_from_content(str(v.get("content", ""))) is not None
            ]
            if leaked_in_zip:
                findings.append(
                    f"votos_criptografados.json no pacote ZIP expõe id_voto em texto plano ({len(leaked_in_zip)} cédula(s))."
                )
    return findings, notes, zip_ids


def auditar_api_publica(
    base_url: str,
    election_id: int,
    ground_truth: list[SubmittedVote],
    db_votes: list[dict[str, Any]],
    ctx: dict[str, Any],
) -> CheckResult:
    """A6: Audita sigilo nas respostas de /vote/cast/ e nos endpoints públicos da API."""
    findings: list[str] = []
    details: list[str] = []

    # 1. Conferência das respostas de /api/vote/cast/ (quando houve submissão)
    for gt in ground_truth:
        resp = gt.cast_response
        leaked_keys = [k for k in ("receipt", "id_generated", "id_voto", "choices") if k in resp]
        if leaked_keys:
            findings.append(f"Resposta de /api/vote/cast/ vazou campo(s) sensível(is): {leaked_keys}")

    # 2. Consulta aos endpoints públicos
    pub_url = f"{base_url.rstrip('/')}/api/public/elections/{election_id}/"
    try:
        r1 = requests.get(pub_url, timeout=10)
    except requests.RequestException as exc:
        if not ground_truth:
            return CheckResult(
                code="A6",
                title="Sigilo nas Respostas e Endpoints Públicos da API",
                status="ALERTA",
                summary=f"Servidor API inacessível em {base_url} durante auditoria offline.",
                details=details + [f"Erro de conexão: {exc}"],
            )
        return CheckResult(
            code="A6",
            title="Sigilo nas Respostas e Endpoints Públicos da API",
            status="FALHOU",
            summary="Falha ao consultar endpoint público da API após submissão.",
            details=findings + details + [f"Erro de conexão: {exc}"],
        )

    if r1.status_code != 200:
        details.append(f"GET {pub_url} retornou HTTP {r1.status_code}.")
        return CheckResult(
            code="A6",
            title="Sigilo nas Respostas e Endpoints Públicos da API",
            status="ALERTA" if not findings else "FALHOU",
            summary=f"Endpoint público retornou HTTP {r1.status_code}.",
            details=findings + details,
        )

    pub_data = r1.json()
    ec_pub = pub_data.get("electoral_college") or []
    exposed_voted_at = [item for item in ec_pub if "voted_at" in item]
    if exposed_voted_at:
        findings.append(
            f"Endpoint público expõe campo 'voted_at' para {len(exposed_voted_at)} eleitor(es)."
        )
        for item in exposed_voted_at[:5]:
            details.append(f"  [API PÚBLICA] {item.get('full_name')} -> voted_at={item.get('voted_at')}")
    else:
        details.append("Endpoint público de quórum não expõe 'voted_at'.")

    pub_votes = pub_data.get("votes") or []
    if pub_data.get("status") == "TALLIED" and pub_votes:
        pub_ids = [str(v.get("id_generated")) for v in pub_votes if v.get("id_generated")]
        leaked_id_voto = [
            v.get("id_generated")
            for v in pub_votes
            if extract_id_voto_from_content(str(v.get("content", ""))) is not None
        ]
        if leaked_id_voto:
            findings.append(
                f"Lista 'votes' na API pública expõe id_voto em content ({len(leaked_id_voto)} cédula(s))."
            )

        vote_pk_is_int = any(
            t in str(ctx["cols"]["Domain_vote"].get("id", {}).get("data_type", "")).lower()
            for t in ("int", "serial", "bigint", "integer")
        )
        db_ids_by_pk = [str(v["id_generated"]) for v in db_votes]
        if vote_pk_is_int and len(pub_ids) >= 2 and pub_ids == db_ids_by_pk:
            findings.append("Lista 'votes' na API pública segue ordem de PK inteira sequencial.")

        is_hash_sorted = pub_ids == sorted(pub_ids)
        details.append(
            f"Ordenação de 'votes' na API pública: {'por id_generated (hash SHA-256 aleatório)' if is_hash_sorted else 'não ordenada por id_generated'}."
        )

        zip_findings, zip_notes, zip_ids = _inspecionar_ordem_zip_auditoria(base_url, election_id)
        findings.extend(zip_findings)
        details.extend(zip_notes)
        if zip_ids and vote_pk_is_int and len(zip_ids) >= 2 and zip_ids == db_ids_by_pk:
            findings.append("votos_criptografados.json no pacote ZIP segue ordem de PK inteira sequencial.")

        if ground_truth and len(ground_truth) >= MIN_SAMPLE_STOCHASTIC:
            gt_sorted = sorted(ground_truth, key=lambda g: g.cast_at)
            pub_idx_by_content = {str(v.get("content", "")): idx + 1 for idx, v in enumerate(pub_votes)}
            sub_ranks: list[float] = []
            pub_ranks: list[float] = []
            for idx, gt in enumerate(gt_sorted):
                pos = pub_idx_by_content.get(gt.pacote_cifrado) or pub_idx_by_content.get(gt.content)
                if pos is not None:
                    sub_ranks.append(float(idx + 1))
                    pub_ranks.append(float(pos))
            rho_pub = spearman_rho(sub_ranks, pub_ranks) if len(sub_ranks) >= 2 else None
            if rho_pub is not None:
                details.append(f"Correlação de ordem API pública vs submissão (N={len(sub_ranks)}): Spearman rho={rho_pub:+.4f}.")
                if rho_pub >= 0.85:
                    findings.append(f"Ordem pública de 'votes' correlaciona com ordem cronológica (Spearman rho={rho_pub:+.4f}).")
    else:
        details.append(
            f"Status público='{pub_data.get('status')}'; votes publicados={len(pub_votes)}, "
            f"private_key publicada={bool(pub_data.get('private_key'))}."
        )

    if findings:
        return CheckResult(
            code="A6",
            title="Sigilo nas Respostas e Endpoints Públicos da API",
            status="FALHOU",
            summary=findings[0],
            details=findings + details,
        )

    return CheckResult(
        code="A6",
        title="Sigilo nas Respostas e Endpoints Públicos da API",
        status="PASSOU",
        summary="Endpoints públicos e respostas da API não expõem vínculos entre eleitor e cédula.",
        details=details,
    )


# ==============================================================================
# Interface CLI e Relatório Final
# ==============================================================================
def carregar_tokens(args: argparse.Namespace) -> list[str]:
    tokens = [t.strip() for t in (args.tokens or []) if t.strip() and t.strip() != "SEU_TOKEN_DE_VOTACAO_AQUI"]
    if args.tokens_file:
        path = Path(args.tokens_file)
        for line in path.read_text(encoding="utf-8").splitlines():
            clean = line.strip()
            if clean and not clean.startswith("#"):
                tokens.append(clean)
    return tokens


def listar_eleicoes_resumo(db: DBAdapter) -> None:
    if not db.table_exists("Domain_election"):
        return
    rows = db.query_all(
        """
        SELECT e.id, e.title, e.status,
               (SELECT COUNT(*) FROM "Domain_electoralcollege" ec WHERE ec.election_id = e.id AND ec.has_voted = %s) AS voted_count,
               (SELECT COUNT(*) FROM "Domain_vote" v WHERE v.election_id = e.id) AS votes_count
        FROM "Domain_election" e
        ORDER BY e.id ASC
        """,
        (True,),
    )
    if not rows:
        print("Nenhuma eleição cadastrada no banco.")
        return
    print("\nEleições disponíveis no banco:")
    print(f"  {'ID':>4}  {'Status':<8}  {'Votantes':>8}  {'Urna':>6}  Título")
    print("  " + "-" * 60)
    for r in rows:
        print(f"  {r['id']:>4}  {r['status']:<8}  {r['voted_count']:>8}  {r['votes_count']:>6}  {r['title']}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Teste 2 (Eixo 1): Auditoria de Sigilo do Voto na API e no Banco de Dados.",
    )
    parser.add_argument("tokens", nargs="*", help="Tokens de votação de uso único para submeter votos sucessivos.")
    parser.add_argument("--tokens-file", help="Arquivo com um token de votação por linha.")
    parser.add_argument("--election-id", type=int, help="ID da eleição a auditar no banco e API pública.")
    parser.add_argument("--audit-only", action="store_true", help="Executa apenas a auditoria SQL + API sem submeter votos.")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help=f"URL base da API (padrão: {DEFAULT_BASE_URL}).")
    parser.add_argument("--delay-ms", type=int, default=DEFAULT_DELAY_MS, help=f"Atraso entre votos sucessivos em ms (padrão: {DEFAULT_DELAY_MS}).")
    parser.add_argument("--window-ms", type=float, default=DEFAULT_WINDOW_MS, help=f"Janela temporal de correlação em ms (padrão: {DEFAULT_WINDOW_MS:.0f}).")
    parser.add_argument("--db-url", help="DSN PostgreSQL explícito (ex.: postgresql://user:pass@host:5432/db).")
    parser.add_argument("--sqlite", type=Path, help="Caminho explícito para um banco SQLite.")
    parser.add_argument("--env-file", type=Path, default=DEFAULT_ENV_PATH, help=f"Arquivo .env do backend (padrão: {DEFAULT_ENV_PATH}).")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    tokens = carregar_tokens(args)

    try:
        db = DBAdapter.connect(db_url=args.db_url, sqlite_path=args.sqlite, env_path=args.env_file)
    except Exception as exc:
        print(f"Erro ao conectar ao banco de dados: {exc}", file=sys.stderr)
        return 2

    try:
        if args.audit_only and args.election_id is None:
            print("Erro: --audit-only exige --election-id <ID>.", file=sys.stderr)
            listar_eleicoes_resumo(db)
            return 2

        if not tokens and args.election_id is None:
            print("Uso:")
            print("  python3 sigiloVoto.py <TOKEN_1> <TOKEN_2> ... [--election-id ID]")
            print("  python3 sigiloVoto.py --tokens-file tokens.txt")
            print("  python3 sigiloVoto.py --audit-only --election-id ID")
            listar_eleicoes_resumo(db)
            return 2

        ground_truth: list[SubmittedVote] = []
        if not args.audit_only and tokens:
            api_pub = carregar_chave_api()
            print(f"Submetendo {len(tokens)} voto(s) legítimo(s) em {args.base_url} (intervalo {args.delay_ms} ms)...")
            for idx, raw_token in enumerate(tokens):
                sv = submeter_voto_legitimo(args.base_url, api_pub, raw_token, idx)
                ground_truth.append(sv)
                print(
                    f"  Voto {idx + 1}/{len(tokens)}: {sv.voter_name} <{sv.voter_email}> "
                    f"(eleição #{sv.election_id}) -> escolhas={sv.choice_labels} -> CONFIRMED"
                )
                if idx + 1 < len(tokens) and args.delay_ms > 0:
                    time.sleep(args.delay_ms / 1000.0)

        election_id = args.election_id
        if election_id is None:
            election_ids = {sv.election_id for sv in ground_truth}
            if len(election_ids) != 1:
                print(f"Erro: tokens pertencem a múltiplas eleições ({sorted(election_ids)}); informe --election-id.", file=sys.stderr)
                return 2
            election_id = next(iter(election_ids))

        el_rows = db.query_all(
            'SELECT id, title, status FROM "Domain_election" WHERE id = %s',
            (election_id,),
        )
        if not el_rows:
            print(f"Erro: Eleição #{election_id} não encontrada no banco ({db.description}).", file=sys.stderr)
            listar_eleicoes_resumo(db)
            return 2
        election_info = el_rows[0]

        ctx: dict[str, Any] = {}
        checks = [
            auditar_esquema_relacional(db, ctx),
            auditar_conteudo_e_tickets(db, election_id, ctx),
            auditar_correlacao_temporal(db, election_id, args.window_ms, ground_truth, ctx),
            auditar_correlacao_estocastica_ordem(db, election_id, ground_truth, ctx),
            auditar_metadados_transacionais_pg(db, election_id, election_info["status"], ctx),
            auditar_api_publica(args.base_url, election_id, ground_truth, ctx.get("votes", []), ctx),
        ]

        print("\n" + "=" * 78)
        print("AUDITORIA DE SIGILO DO VOTO (EIXO 1 - TESTE 2)")
        print("=" * 78)
        print(f"Eleição : #{election_info['id']} - {election_info['title']} [status={election_info['status']}]")
        print(f"Banco   : {db.description}")
        print(f"API     : {args.base_url}")
        for note in db.notes:
            print(f"Aviso   : {note}")
        print(
            f"Contagem: eleitores={len(ctx.get('voters', []))} | votaram={len(ctx.get('voters_voted', []))} | "
            f"tokens={len(ctx.get('tokens', []))} | votos_urna={len(ctx.get('votes', []))}"
        )
        print("-" * 78)

        for chk in checks:
            print(f"[{chk.status:<6}] {chk.code} - {chk.title}: {chk.summary}")
            for line in chk.details:
                print(f"           {line}")

        print("=" * 78)
        has_fail = any(c.status == "FALHOU" for c in checks)
        has_alert = any(c.status == "ALERTA" for c in checks)
        voted_count = len(ctx.get("voters_voted", []))

        if has_fail:
            print("Resultado: REPROVADO")
            return 1
        if has_alert or voted_count < 2:
            print(
                "Resultado: INCONCLUSIVO (amostra insuficiente — submeta ao menos 2 votos, "
                f"recomendado >= {MIN_SAMPLE_STOCHASTIC})"
            )
            return 1

        print("Resultado: APROVADO")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
