"""
Teste 1: Prevenção de Voto Duplo e Concorrência na API (Eixo 1)
Dispara N requisições assíncronas simultâneas para /api/vote/cast/ utilizando
o mesmo token e credencial de um único votante em janela de milissegundos.
"""

import asyncio
import base64
import datetime
import json
import os
import struct
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID

# ==============================================================================
# Configuração direta do ensaio
# ==============================================================================
BASE_URL = "http://127.0.0.1:8000"
TOKEN = sys.argv[1] if len(sys.argv) > 1 else "SEU_TOKEN_DE_VOTACAO_AQUI"
NUM_REQUISICOES = 15
SE_KEYS_PATH = Path("/home/debrito/Programação/votaai-backend/se_keys_info.json")


def carregar_chave_api() -> rsa.RSAPublicKey:
    keys = json.loads(SE_KEYS_PATH.read_text(encoding="utf-8"))
    entry = next(k for k in keys if k["KeyName"] == "VotaAI_SecureKey_2")
    blob = base64.b64decode(entry["PublicKeyBase64"])
    _, _, cb_exp, cb_mod, _, _ = struct.unpack("<IIIIII", blob[:24])
    e = int.from_bytes(blob[24 : 24 + cb_exp], "big")
    n = int.from_bytes(blob[24 + cb_exp : 24 + cb_exp + cb_mod], "big")
    return rsa.RSAPublicNumbers(e, n).public_key()


def gerar_certificado_strongbox(dev_priv: rsa.RSAPrivateKey, challenge: str) -> str:
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


def cifrar_envelope(pub_key: rsa.RSAPublicKey, payload: dict) -> dict:
    aes_key, iv = os.urandom(32), os.urandom(12)
    ct_tag = AESGCM(aes_key).encrypt(iv, json.dumps(payload).encode("utf-8"), None)
    return {
        "encrypted_payload": base64.b64encode(ct_tag[:-16]).decode("utf-8"),
        "encrypted_aes_key": base64.b64encode(pub_key.encrypt(aes_key, padding.PKCS1v15())).decode("utf-8"),
        "iv": base64.b64encode(iv).decode("utf-8"),
        "tag": base64.b64encode(ct_tag[-16:]).decode("utf-8"),
    }


def decifrar_resposta(dev_priv: rsa.RSAPrivateKey, raw_text: str):
    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError:
        return raw_text
    if isinstance(data, dict) and {"encrypted_payload", "encrypted_aes_key", "iv", "tag"} <= data.keys():
        aes_key = dev_priv.decrypt(base64.b64decode(data["encrypted_aes_key"]), padding.PKCS1v15())
        plain = AESGCM(aes_key).decrypt(
            base64.b64decode(data["iv"]),
            base64.b64decode(data["encrypted_payload"]) + base64.b64decode(data["tag"]),
            None,
        )
        return json.loads(plain.decode("utf-8"))
    return data


def solicitar_cedula(api_pub: rsa.RSAPublicKey, dev_priv: rsa.RSAPrivateKey, dev_pub_pem: str) -> tuple[str, str]:
    nonce = f"nonce-req-{uuid.uuid4().hex[:12]}"
    envelope = cifrar_envelope(api_pub, {
        "token": TOKEN,
        "machine_public_key": dev_pub_pem,
        "attestation_certificates": [gerar_certificado_strongbox(dev_priv, nonce)],
        "nonce": nonce,
    })
    resp = requests.post(f"{BASE_URL}/api/vote/request/", json=envelope, timeout=15)
    body = decifrar_resposta(dev_priv, resp.text)
    if resp.status_code != 200:
        raise RuntimeError(f"Erro ao solicitar cédula (HTTP {resp.status_code}): {body}")

    id_voto = body["id_voto"]
    election = body["election"]
    election_pub = serialization.load_pem_public_key(election["public_key"].encode("utf-8"))

    choices = {}
    for q in election.get("questions", []):
        options = q.get("options", [])
        if not options:
            continue
        selected = next(
            (opt for opt in options if opt.get("label") not in ("Branco", "Nulo")),
            options[0],
        )
        choices[str(q["id"])] = selected["id"]

    ballot_payload = {"election_id": election["id"], "choices": choices}
    ballot_plain = json.dumps(ballot_payload, separators=(",", ":")).encode("utf-8")
    if len(ballot_plain) > 200:
        pacote_cifrado = json.dumps(cifrar_envelope(election_pub, ballot_payload), separators=(",", ":"))
    else:
        cipher_bytes = election_pub.encrypt(ballot_plain, padding.PKCS1v15())
        pacote_cifrado = base64.b64encode(cipher_bytes).decode("utf-8")

    return id_voto, pacote_cifrado


def preparar_envelopes(
    api_pub: rsa.RSAPublicKey,
    dev_priv: rsa.RSAPrivateKey,
    dev_pub_pem: str,
    id_voto: str,
    pacote_cifrado: str,
) -> list[dict]:
    content = json.dumps({"id_voto": id_voto, "pacote_cifrado": pacote_cifrado}, separators=(",", ":"))
    signature = base64.b64encode(
        dev_priv.sign(content.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256())
    ).decode("utf-8")

    return [
        cifrar_envelope(api_pub, {
            "token": TOKEN,
            "machine_public_key": dev_pub_pem,
            "content": content,
            "id_voto": id_voto,
            "nonce": f"nonce-cast-{i}-{uuid.uuid4().hex[:10]}",
            "signature": signature,
        })
        for i in range(NUM_REQUISICOES)
    ]


async def disparar_concorrente(envelopes: list[dict], dev_priv: rsa.RSAPrivateKey):
    barrier = threading.Barrier(len(envelopes))
    disparos: list[int] = []
    lock = threading.Lock()

    def enviar(idx: int, env: dict):
        with requests.Session() as s:
            barrier.wait(timeout=15)
            t0 = time.perf_counter_ns()
            with lock:
                disparos.append(t0)
            resp = s.post(f"{BASE_URL}/api/vote/cast/", json=env, timeout=15)
            lat_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
            return idx, resp.status_code, decifrar_resposta(dev_priv, resp.text), lat_ms

    loop = asyncio.get_running_loop()
    with ThreadPoolExecutor(max_workers=len(envelopes)) as pool:
        resultados = await asyncio.gather(
            *(loop.run_in_executor(pool, enviar, i + 1, env) for i, env in enumerate(envelopes))
        )

    janela_ms = (max(disparos) - min(disparos)) / 1_000_000.0 if disparos else 0.0
    return resultados, janela_ms


def main() -> int:
    if TOKEN == "SEU_TOKEN_DE_VOTACAO_AQUI":
        print("Informe o token: python3 prevencaoVotoDuplo.py <TOKEN>")
        return 2

    api_pub = carregar_chave_api()
    dev_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    dev_pub_pem = dev_priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    id_voto, pacote_cifrado = solicitar_cedula(api_pub, dev_priv, dev_pub_pem)
    envelopes = preparar_envelopes(api_pub, dev_priv, dev_pub_pem, id_voto, pacote_cifrado)
    resultados, janela_ms = asyncio.run(disparar_concorrente(envelopes, dev_priv))

    aceitas = [r for r in resultados if r[1] in (200, 201) and isinstance(r[2], dict) and r[2].get("status") == "CONFIRMED"]
    rejeitadas = [r for r in resultados if r[1] in (400, 403, 409, 423, 429)]
    inesperadas = [r for r in resultados if r not in aceitas and r not in rejeitadas]

    print(f"Disparadas: {NUM_REQUISICOES} | Janela: {janela_ms:.2f} ms")
    print(f"Aceitas (200 CONFIRMED): {len(aceitas)} | Rejeitadas (4xx): {len(rejeitadas)} | Outras/5xx: {len(inesperadas)}")
    for idx, code, body, lat in resultados:
        print(f"  Req {idx:02d}: HTTP {code} ({lat:.1f} ms) -> {body}")

    aprovado = len(aceitas) == 1 and len(rejeitadas) == NUM_REQUISICOES - 1 and not inesperadas
    print(f"\nResultado: {'APROVADO' if aprovado else 'REPROVADO'}")
    return 0 if aprovado else 1


if __name__ == "__main__":
    raise SystemExit(main())
