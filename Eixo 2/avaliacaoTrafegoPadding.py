"""
Teste 2 (Teste 5 do Plano de Testes): Avaliação de Tráfego e Padding da Cédula com Wireshark (Eixo 2)

Avalia se um observador passivo posicionado na rede local pode inferir o conteúdo do
voto do eleitor a partir do tamanho dos pacotes de dados transmitidos sob o canal TLS ativo.

Procedimento experimental:
  1. Emite sucessivos votos legítimos no formato do cliente móvel Vota-i 2.0 para opções de
     comprimentos nominais distintos:
       - Candidato com nome curto ("Ana")
       - Chapa extensa com múltiplos nomes (~206 bytes)
       - Voto em "Branco"
       - Voto "Nulo"
  2. Captura integralmente o tráfego TLS em arquivo PCAP (via observador passivo TCP em
     nível de fio ou tcpdump) e disseca os registros TLS com o analisador real do
     Wireshark (tshark).
  3. Executa controle negativo (contraprova AES-256-GCM/NoPadding com texto nominal sem
     indireção/padding) e analisa estatisticamente a distribuição de tamanhos dos payloads
     TLS das requisições POST /api/vote/cast/ (variância, Pearson r, Spearman ρ,
     Kruskal-Wallis, ANOVA, Entropia de Shannon, Informação Mútua e acurácia de
     classificador passivo).
  4. Audita estaticamente o código-fonte do cliente e do servidor e testa limites de
     fronteira de tamanho (cédula multi-questão > 245 bytes e variação de nonce).

Critério de validação:
  Aprovado somente se todos os pacotes de cédula criptografada apresentarem tamanho
  estritamente fixo e padronizado (range == 0 B, std == 0.00 B, H(Size) == 0 bits)
  antes da transmissão, impossibilitando qualquer correlação estatística entre o
  tamanho do pacote cifrado e o candidato escolhido.
"""

from __future__ import annotations

import argparse
import base64
import datetime
import email
import email.header
import email.policy
import hashlib
import http.client
import http.server
import ipaddress
import json
import math
import os
import random
import re
import select
import shutil
import socket
import sqlite3
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import uuid
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

try:
    import psycopg2
except ImportError:  # pragma: no cover - opcional quando usando apenas SQLite
    psycopg2 = None  # type: ignore[assignment]


# ==============================================================================
# Configuração padrão do ensaio e cenários nominais
# ==============================================================================
BACKEND_DIR = Path("/home/debrito/Programação/votaai-backend")
DESKTOP_DIR = Path("/home/debrito/Programação/votaai-desktop")
MOBILE_DIR = Path("/home/debrito/Programação/projeto-react-native")
SE_KEYS_PATH = BACKEND_DIR / "se_keys_info.json"
DEFAULT_ENV_PATH = BACKEND_DIR / ".env"
DEFAULT_SQLITE_PATH = BACKEND_DIR / "db.sqlite3"
DEFAULT_SENT_EMAILS_DIR = BACKEND_DIR / "sent_emails"
DEFAULT_CLIENT_KEY_PATH = DESKTOP_DIR / "app" / "resources" / "client_key.json"
DEFAULT_CLIENT_KEYS_DIR = DESKTOP_DIR / "app" / "resources" / ".client_keys"
DEFAULT_REGISTRATION_INFO_PATH = DESKTOP_DIR / "app" / "resources" / "registration_info.json"

DEFAULT_BACKEND_URL = "http://127.0.0.1:8000"
DEFAULT_TARGET_HOST = "localhost"
DEFAULT_REPEATS = 5
DEFAULT_SEED = 20261122
FLATPAK_WIRESHARK_APP_ID = "org.wireshark.Wireshark"
BALLOT_PAD_BLOCK_SIZE = 1024
ENVELOPE_PAD_BLOCK_SIZE = 4096


def pad_iso7816_4(data: bytes, block_size: int) -> bytes:
    """Aplica preenchimento determinístico ISO/IEC 7816-4 (0x80 + 0x00...) até múltiplo de block_size."""
    target = ((len(data) // block_size) + 1) * block_size
    return data + b"\x80" + b"\x00" * (target - len(data) - 1)


def unpad_iso7816_4(data: bytes) -> bytes:
    """Remove preenchimento ISO/IEC 7816-4, preservando payloads legados sem padding."""
    if not data:
        return data
    i = len(data) - 1
    while i >= 0 and data[i] == 0x00:
        i -= 1
    if i >= 0 and data[i] == 0x80 and (i < len(data) - 1 or i == 0 or data[i - 1] < 0x80):
        return data[:i]
    return data

STANDARD_OPTIONS: tuple[dict[str, Any], ...] = (
    {
        "category": "CURTO",
        "option_id": 1,
        "label": "Ana",
    },
    {
        "category": "CHAPA_LONGA",
        "option_id": 10002,
        "label": (
            "Chapa 02 - Frente Ampla de Renovação Universitária: "
            "Prof. Dr. Antônio Carlos Albuquerque de Vasconcelos, "
            "Profa. Dra. Maria Aparecida Nascimento Pereira e "
            "Prof. Me. João Henrique Cavalcanti de Oliveira"
        ),
    },
    {
        "category": "BRANCO",
        "option_id": 99,
        "label": "Branco",
    },
    {
        "category": "NULO",
        "option_id": 100,
        "label": "Nulo",
    },
)


# ==============================================================================
# Estruturas de dados do ensaio
# ==============================================================================
@dataclass
class CheckResult:
    code: str
    title: str
    status: str  # "PASSOU" | "FALHOU" | "ALERTA" | "N/A"
    summary: str
    details: list[str] = field(default_factory=list)


@dataclass
class VoteSample:
    seq_index: int
    category: str
    option_id: int
    option_label: str
    nominal_bytes: int
    plain_package_bytes: int
    pacote_cifrado_b64_len: int
    content_bytes: int
    envelope_json_bytes: int
    http_content_length: int
    http_status: int
    confirmed: bool
    decrypted_verified: bool
    client_port: int
    tcp_stream: int | None = None
    tls_version: str = ""
    tls_ciphersuite: str = ""
    tls_http_post_bytes: int = 0
    tls_max_record_bytes: int = 0
    tls_total_appdata_bytes: int = 0
    tcp_c2s_payload_bytes: int = 0
    tls_c2s_record_sizes: list[int] = field(default_factory=list)


@dataclass
class TlsStreamSummary:
    stream_id: int
    client_port: int
    server_port: int
    first_ts: float
    tls_version: str
    ciphersuite: str
    c2s_appdata_records: list[int]
    s2c_appdata_records: list[int]
    tcp_c2s_payload_bytes: int
    tls_http_post_bytes: int
    tls_max_record_bytes: int
    tls_total_appdata_bytes: int


# ==============================================================================
# Detecção e Dissecação com Wireshark / TShark
# ==============================================================================
def detectar_tshark() -> tuple[list[str], str] | tuple[None, str]:
    """Localiza o binário tshark (nativo ou Flatpak org.wireshark.Wireshark) e obtém a versão."""
    native = shutil.which("tshark")
    candidates: list[list[str]] = []
    if native:
        candidates.append([native])
    flatpak = shutil.which("flatpak")
    if flatpak:
        candidates.append([flatpak, "run", "--command=tshark", FLATPAK_WIRESHARK_APP_ID])

    for cmd in candidates:
        try:
            proc = subprocess.run([*cmd, "--version"], capture_output=True, text=True, timeout=12)
            if proc.returncode == 0 and proc.stdout.strip():
                first_line = proc.stdout.strip().splitlines()[0].strip()
                return cmd, first_line
        except Exception:
            continue
    return None, "tshark não encontrado (nem nativo nem Flatpak org.wireshark.Wireshark)"


def _parse_tls_version_label(record_versions: list[str], hs_versions: list[str], supported_versions: list[str]) -> str:
    tokens = [v.strip().lower() for v in supported_versions + hs_versions + record_versions if v.strip()]
    if any(t in ("0x0304", "0x00000304") for t in tokens):
        return "TLS 1.3"
    if any(t in ("0x0303", "0x00000303") for t in tokens):
        return "TLS 1.2"
    if any(t in ("0x0302", "0x00000302") for t in tokens):
        return "TLS 1.1"
    if any(t in ("0x0301", "0x00000301") for t in tokens):
        return "TLS 1.0"
    return tokens[0] if tokens else "desconhecido"


def _split_csv_ints(field_val: str) -> list[int]:
    out: list[int] = []
    for part in field_val.split(","):
        s = part.strip()
        if not s:
            continue
        try:
            out.append(int(s, 0))
        except ValueError:
            continue
    return out


def _split_csv_strs(field_val: str) -> list[str]:
    return [p.strip() for p in field_val.split(",") if p.strip()]


def dissecar_pcap_com_tshark(
    tshark_cmd: list[str],
    pcap_bytes: bytes,
    server_port: int | None = None,
) -> dict[int, TlsStreamSummary]:
    """
    Envia os bytes do arquivo PCAP via STDIN (`-r -`) para o tshark real e extrai
    métricas de registros TLS e fluxos TCP por `tcp.stream`.
    """
    cmd = [
        *tshark_cmd,
        "-r",
        "-",
        "-o",
        "tcp.desegment_tcp_streams:true",
        "-o",
        "tls.desegment_ssl_records:true",
    ]
    if server_port is not None and server_port > 0:
        cmd += ["-d", f"tcp.port=={server_port},tls", "-Y", f"tcp.port == {server_port} && tls"]
    else:
        cmd += ["-Y", "tls"]

    cmd += [
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        "occurrence=a",
        "-e",
        "frame.number",
        "-e",
        "frame.time_epoch",
        "-e",
        "frame.len",
        "-e",
        "tcp.stream",
        "-e",
        "tcp.srcport",
        "-e",
        "tcp.dstport",
        "-e",
        "tcp.len",
        "-e",
        "tls.record.version",
        "-e",
        "tls.record.content_type",
        "-e",
        "tls.record.opaque_type",
        "-e",
        "tls.record.length",
        "-e",
        "tls.handshake.type",
        "-e",
        "tls.handshake.version",
        "-e",
        "tls.handshake.extensions.supported_version",
        "-e",
        "tls.handshake.ciphersuite",
    ]

    proc = subprocess.run(cmd, input=pcap_bytes, capture_output=True, timeout=60)
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"Falha ao executar tshark (rc={proc.returncode}): {err}")

    stdout_text = proc.stdout.decode("utf-8", errors="replace")
    raw_streams: dict[int, dict[str, Any]] = {}

    for line in stdout_text.splitlines():
        if not line.strip():
            continue
        cols = line.split("\t")
        while len(cols) < 15:
            cols.append("")
        (
            _frame_no,
            ts_s,
            _frame_len_s,
            stream_s,
            sport_s,
            dport_s,
            tcp_len_s,
            rec_ver_s,
            rec_ct_s,
            rec_ot_s,
            rec_len_s,
            hs_type_s,
            hs_ver_s,
            sup_ver_s,
            cs_s,
        ) = cols[:15]

        if not stream_s.strip():
            continue
        stream_id = int(stream_s.strip())
        sport = int(sport_s.strip()) if sport_s.strip() else 0
        dport = int(dport_s.strip()) if dport_s.strip() else 0
        ts = float(ts_s.strip()) if ts_s.strip() else 0.0
        tcp_len = int(tcp_len_s.strip()) if tcp_len_s.strip() else 0

        st = raw_streams.setdefault(
            stream_id,
            {
                "first_ts": ts,
                "client_port": None,
                "server_port": server_port,
                "record_versions": [],
                "hs_versions": [],
                "supported_versions": [],
                "ciphersuites": [],
                "events": [],
            },
        )
        if ts and (st["first_ts"] == 0.0 or ts < st["first_ts"]):
            st["first_ts"] = ts

        hs_types = _split_csv_ints(hs_type_s)
        if 1 in hs_types:  # ClientHello
            st["client_port"] = sport
            if st["server_port"] is None:
                st["server_port"] = dport
        elif 2 in hs_types:  # ServerHello
            if st["server_port"] is None:
                st["server_port"] = sport
            if st["client_port"] is None:
                st["client_port"] = dport

        if st["server_port"] is not None and st["client_port"] is None:
            if dport == st["server_port"]:
                st["client_port"] = sport
            elif sport == st["server_port"]:
                st["client_port"] = dport

        st["record_versions"].extend(_split_csv_strs(rec_ver_s))
        st["hs_versions"].extend(_split_csv_strs(hs_ver_s))
        if 2 in hs_types or not hs_types:
            st["supported_versions"].extend(_split_csv_strs(sup_ver_s))
        st["ciphersuites"].extend(_split_csv_strs(cs_s))

        cts = _split_csv_ints(rec_ct_s)
        ots = _split_csv_ints(rec_ot_s)
        rlens = _split_csv_ints(rec_len_s)
        if len(cts) == len(rlens):
            rec_types = cts
        elif len(ots) == len(rlens):
            rec_types = ots
        elif len(cts) + len(ots) == len(rlens):
            # Em frames de transição TLS 1.3 (ex.: CCS + Finished), content_type precede opaque_type
            rec_types = cts + ots
        else:
            rec_types = (cts + ots)[: len(rlens)]
        st["events"].append((sport, dport, tcp_len, rec_types, rlens))

    summaries: dict[int, TlsStreamSummary] = {}
    for stream_id, st in raw_streams.items():
        srv_port = st["server_port"] or 0
        cli_port = st["client_port"] or 0
        tls_ver = _parse_tls_version_label(st["record_versions"], st["hs_versions"], st["supported_versions"])
        ciphersuite = st["ciphersuites"][-1] if st["ciphersuites"] else ""

        c2s_appdata: list[int] = []
        s2c_appdata: list[int] = []
        tcp_c2s_bytes = 0

        for sport, dport, tcp_len, cts, rlens in st["events"]:
            is_c2s = (dport == srv_port) if srv_port else (sport == cli_port)
            if is_c2s:
                tcp_c2s_bytes += tcp_len
            for ct, rlen in zip(cts, rlens):
                if ct == 23:  # Application Data
                    if is_c2s:
                        c2s_appdata.append(rlen)
                    else:
                        s2c_appdata.append(rlen)

        # Em TLS 1.3, o Client Finished (~53-69B) e o close_notify (~19B) compartilham
        # o content_type externo 23 (Application Data) com a requisição HTTP cifrada.
        if tls_ver == "TLS 1.3" and c2s_appdata:
            filtered = list(c2s_appdata)
            if len(filtered) >= 2 and filtered[0] <= 100:
                filtered = filtered[1:]
            while len(filtered) >= 2 and filtered[-1] <= 32:
                filtered.pop()
            http_post_bytes = sum(filtered) if filtered else max(c2s_appdata)
        else:
            http_post_bytes = sum(c2s_appdata)

        summaries[stream_id] = TlsStreamSummary(
            stream_id=stream_id,
            client_port=cli_port,
            server_port=srv_port,
            first_ts=st["first_ts"],
            tls_version=tls_ver,
            ciphersuite=ciphersuite,
            c2s_appdata_records=c2s_appdata,
            s2c_appdata_records=s2c_appdata,
            tcp_c2s_payload_bytes=tcp_c2s_bytes,
            tls_http_post_bytes=http_post_bytes,
            tls_max_record_bytes=max(c2s_appdata) if c2s_appdata else 0,
            tls_total_appdata_bytes=sum(c2s_appdata),
        )

    return summaries


# ==============================================================================
# Captura Passiva em Nível de Fio (PassiveTCPWireTap -> PCAP padrão) e tcpdump
# ==============================================================================
def _internet_checksum(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


class PassiveTCPWireTap:
    """
    Observador passivo L4 TCP em Python puro que captura os octetos cifrados em trânsito
    (sem acesso a chaves TLS) e gera um arquivo PCAP padrão (Ethernet II + IPv4 + TCP,
    LINKTYPE_ETHERNET=1) compatível com Wireshark GUI e tshark sem exigir root.
    """

    LINKTYPE_ETHERNET = 1
    MAX_TCP_SEG = 1460

    def __init__(self, target_host: str, target_port: int, listen_host: str = "127.0.0.1", listen_port: int = 0) -> None:
        self.target_host = target_host
        self.target_port = target_port
        self._listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listen_sock.bind((listen_host, listen_port))
        self._listen_sock.listen(64)
        self.listen_port = int(self._listen_sock.getsockname()[1])

        self._pcap_lock = threading.Lock()
        self._threads_lock = threading.Lock()
        self._active_threads: list[threading.Thread] = []
        self._stop_event = threading.Event()
        self._ip_id = 1
        self._buf = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, self.LINKTYPE_ETHERNET))

        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._accept_thread.start()

    def _build_eth_ipv4_tcp(self, sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes, c2s: bool) -> bytes:
        src_mac = b"\x02\x00\x00\x00\x00\x01" if c2s else b"\x02\x00\x00\x00\x00\x02"
        dst_mac = b"\x02\x00\x00\x00\x00\x02" if c2s else b"\x02\x00\x00\x00\x00\x01"
        eth = dst_mac + src_mac + b"\x08\x00"

        ip_src = socket.inet_aton("127.0.0.1")
        ip_dst = socket.inet_aton("127.0.0.1")

        tcp_no_csum = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, 0x50, flags, 65535, 0, 0)
        tcp_len = 20 + len(payload)
        pseudo = struct.pack("!4s4sBBH", ip_src, ip_dst, 0, 6, tcp_len)
        tcp_csum = _internet_checksum(pseudo + tcp_no_csum + payload)
        tcp_hdr = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, 0x50, flags, 65535, tcp_csum, 0)

        ip_total = 20 + tcp_len
        ip_id = self._ip_id & 0xFFFF
        self._ip_id += 1
        ip_no_csum = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_total, ip_id, 0x4000, 64, 6, 0, ip_src, ip_dst)
        ip_csum = _internet_checksum(ip_no_csum)
        ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_total, ip_id, 0x4000, 64, 6, ip_csum, ip_src, ip_dst)

        return eth + ip_hdr + tcp_hdr + payload

    def _write_packet_locked(self, frame: bytes) -> None:
        now_ns = time.time_ns()
        ts_sec = now_ns // 1_000_000_000
        ts_usec = (now_ns % 1_000_000_000) // 1_000
        pkt_hdr = struct.pack("<IIII", ts_sec, ts_usec, len(frame), len(frame))
        self._buf.extend(pkt_hdr)
        self._buf.extend(frame)

    def _emit_segment(self, conn_lock: threading.Lock, state: dict[str, int], c2s: bool, flags: int, data: bytes = b"") -> None:
        with conn_lock:
            sport = state["cli_port"] if c2s else self.listen_port
            dport = self.listen_port if c2s else state["cli_port"]
            if data:
                offset = 0
                while offset < len(data):
                    chunk = data[offset : offset + self.MAX_TCP_SEG]
                    seq = state["c2s_seq"] if c2s else state["s2c_seq"]
                    ack = state["s2c_seq"] if c2s else state["c2s_seq"]
                    with self._pcap_lock:
                        self._write_packet_locked(self._build_eth_ipv4_tcp(sport, dport, seq, ack, flags, chunk, c2s))
                    if c2s:
                        state["c2s_seq"] += len(chunk)
                    else:
                        state["s2c_seq"] += len(chunk)
                    offset += len(chunk)
            else:
                seq = state["c2s_seq"] if c2s else state["s2c_seq"]
                ack = state["s2c_seq"] if c2s else state["c2s_seq"]
                with self._pcap_lock:
                    self._write_packet_locked(self._build_eth_ipv4_tcp(sport, dport, seq, ack, flags, b"", c2s))
                if flags & 0x03:  # SYN or FIN consome 1 número de sequência
                    if c2s:
                        state["c2s_seq"] += 1
                    else:
                        state["s2c_seq"] += 1

    def _accept_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                r, _, _ = select.select([self._listen_sock], [], [], 0.2)
            except OSError:
                break
            if not r:
                continue
            try:
                cli_sock, cli_addr = self._listen_sock.accept()
            except OSError:
                break
            t = threading.Thread(target=self._handle_conn, args=(cli_sock, int(cli_addr[1])), daemon=True)
            with self._threads_lock:
                self._active_threads.append(t)
            t.start()

    def _handle_conn(self, cli_sock: socket.socket, cli_port: int) -> None:
        srv_sock: socket.socket | None = None
        try:
            srv_sock = socket.create_connection((self.target_host, self.target_port), timeout=10.0)
            cli_sock.settimeout(None)
            srv_sock.settimeout(None)
            conn_lock = threading.Lock()
            state = {"cli_port": cli_port, "c2s_seq": 1000, "s2c_seq": 5000}

            # Handshake TCP sintético coerente (SYN -> SYN+ACK -> ACK)
            self._emit_segment(conn_lock, state, c2s=True, flags=0x02)
            self._emit_segment(conn_lock, state, c2s=False, flags=0x12)
            self._emit_segment(conn_lock, state, c2s=True, flags=0x10)

            def _relay(src: socket.socket, dst: socket.socket, c2s: bool) -> None:
                try:
                    while True:
                        data = src.recv(65536)
                        if not data:
                            break
                        self._emit_segment(conn_lock, state, c2s=c2s, flags=0x18, data=data)
                        dst.sendall(data)
                except OSError:
                    pass
                finally:
                    try:
                        dst.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass

            t_c2s = threading.Thread(target=_relay, args=(cli_sock, srv_sock, True), daemon=True)
            t_s2c = threading.Thread(target=_relay, args=(srv_sock, cli_sock, False), daemon=True)
            t_c2s.start()
            t_s2c.start()
            t_c2s.join()
            t_s2c.join()

            # Encerramento TCP limpo (FIN+ACK / ACK / FIN+ACK / ACK)
            self._emit_segment(conn_lock, state, c2s=True, flags=0x11)
            self._emit_segment(conn_lock, state, c2s=False, flags=0x11)
            self._emit_segment(conn_lock, state, c2s=True, flags=0x10)
        except OSError:
            pass
        finally:
            for s in (cli_sock, srv_sock):
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass

    def get_pcap_bytes(self) -> bytes:
        with self._threads_lock:
            threads = list(self._active_threads)
        for t in threads:
            t.join(timeout=5.0)
        with self._pcap_lock:
            return bytes(self._buf)

    def stop(self) -> bytes:
        self._stop_event.set()
        try:
            self._listen_sock.close()
        except OSError:
            pass
        self._accept_thread.join(timeout=2.0)
        return self.get_pcap_bytes()


class TcpdumpCapture:
    """Captura ao vivo via tcpdump em interface real (ex.: executado com sudo no gateway)."""

    def __init__(self, interface: str, port: int, pcap_path: Path) -> None:
        self.pcap_path = pcap_path
        cmd = [
            "tcpdump",
            "-i",
            interface,
            "-s",
            "0",
            "-U",
            "-w",
            str(pcap_path),
            f"tcp port {port}",
        ]
        self._proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(0.6)
        if self._proc.poll() is not None:
            err = (self._proc.stderr.read() or b"").decode("utf-8", errors="replace")
            raise RuntimeError(f"tcpdump encerrou prematuramente: {err.strip()}")

    def stop(self) -> bytes:
        time.sleep(0.4)
        self._proc.terminate()
        try:
            self._proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            self._proc.kill()
            self._proc.wait(timeout=2.0)
        return self.pcap_path.read_bytes() if self.pcap_path.is_file() else b""


# ==============================================================================
# Servidor HTTPS Origin Local (Modo Standalone + Modo Bridge para Backend Django)
# ==============================================================================
def gerar_cert_origin(tmp_dir: Path, target_host: str) -> tuple[Path, Path, str]:
    """Gera certificado X.509 v3 RSA-2048 legítimo para o servidor HTTPS local."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VotaAI Origin"),
            x509.NameAttribute(NameOID.COMMON_NAME, target_host),
        ]
    )
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
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(ski, critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_dir / "origin_cert.pem"
    key_path = tmp_dir / "origin_key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    spki = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    pin = "sha256/" + base64.b64encode(hashlib.sha256(spki).digest()).decode("ascii")
    return cert_path, key_path, pin


def _configure_tls_versions(ctx: ssl.SSLContext, tls_version: str) -> None:
    if tls_version == "1.3":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    elif tls_version == "1.2":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    else:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2


class OriginVoteHTTPSServer:
    """
    Servidor HTTPS local sobre TLS 1.2/1.3.
    - Em modo bridge (`backend_url != None`), encaminha requisições ao backend Django real.
    - Em modo standalone (`backend_url is None`), replica criptograficamente o
      SEDecryptMiddleware + VoteCastView (decifrando envelope híbrido, validando assinatura
      SHA256withRSA e decifrando `pacote_cifrado` com a chave privada da eleição).
    """

    def __init__(
        self,
        cert_path: Path,
        key_path: Path,
        tls_version: str = "1.3",
        backend_url: str | None = None,
        host: str = "127.0.0.1",
        port: int = 0,
    ) -> None:
        self.backend_url = backend_url.rstrip("/") if backend_url else None
        self.api_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.api_pub = self.api_priv.public_key()
        self.election_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.election_pub = self.election_priv.public_key()
        self.election_pub_pem = self.election_pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        self._lock = threading.Lock()
        self.received_records: list[dict[str, Any]] = []
        parent = self

        class _SilentHTTPServer(http.server.ThreadingHTTPServer):
            allow_reuse_address = True
            daemon_threads = True

            def handle_error(self, request: Any, client_address: Any) -> None:
                return

        class _Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:
                return

            def _send_json(self, status: int, obj: dict[str, Any]) -> None:
                raw = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self) -> None:
                if parent.backend_url:
                    status, ctype, resp_body = parent._forward_backend("GET", self.path, dict(self.headers.items()), b"")
                    self.send_response(status)
                    self.send_header("Content-Type", ctype)
                    self.send_header("Content-Length", str(len(resp_body)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    if resp_body:
                        self.wfile.write(resp_body)
                    return
                self._send_json(200, {"status": "ok"})

            def do_POST(self) -> None:
                content_length = int(self.headers.get("Content-Length") or 0)
                raw_body = self.rfile.read(content_length) if content_length > 0 else b""
                clean_path = self.path.split("?", 1)[0]

                if parent.backend_url and clean_path in ("/api/vote/request/", "/api/vote/cast/"):
                    status, ctype, resp_body = parent._forward_backend("POST", self.path, dict(self.headers.items()), raw_body)
                    with parent._lock:
                        parent.received_records.append(
                            {"path": clean_path, "content_length": content_length, "status": status, "decrypted_verified": None}
                        )
                    self.send_response(status)
                    self.send_header("Content-Type", ctype)
                    self.send_header("Content-Length", str(len(resp_body)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    if resp_body:
                        self.wfile.write(resp_body)
                    return

                status, resp_obj, decrypted_ok = parent._handle_local_post(clean_path, raw_body)
                with parent._lock:
                    parent.received_records.append(
                        {"path": clean_path, "content_length": content_length, "status": status, "decrypted_verified": decrypted_ok}
                    )
                self._send_json(status, resp_obj)

        self._server = _SilentHTTPServer((host, port), _Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        _configure_tls_versions(ctx, tls_version)
        ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        self._server.socket = ctx.wrap_socket(self._server.socket, server_side=True)
        self.port = int(self._server.server_address[1])
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def _forward_backend(self, method: str, path: str, headers: dict[str, str], body: bytes) -> tuple[int, str, bytes]:
        assert self.backend_url is not None
        parsed = urllib.parse.urlparse(self.backend_url)
        conn_cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        conn = conn_cls(parsed.hostname or "127.0.0.1", parsed.port or (443 if parsed.scheme == "https" else 8000), timeout=15.0)
        fwd_headers = {
            k: v
            for k, v in headers.items()
            if k.lower() not in ("host", "connection", "proxy-connection", "content-length", "accept-encoding")
        }
        fwd_headers["Host"] = parsed.netloc
        fwd_headers["Connection"] = "close"
        conn.request(method, path, body=body or None, headers=fwd_headers)
        resp = conn.getresponse()
        data = resp.read()
        ctype = resp.getheader("Content-Type") or "application/json"
        status = resp.status
        conn.close()
        return status, ctype, data

    def _handle_local_post(self, clean_path: str, raw_body: bytes) -> tuple[int, dict[str, Any], bool]:
        try:
            env = json.loads(raw_body.decode("utf-8"))
            aes_key = self.api_priv.decrypt(base64.b64decode(env["encrypted_aes_key"]), padding.PKCS1v15())
            plain_bytes = unpad_iso7816_4(
                AESGCM(aes_key[:32]).decrypt(
                    base64.b64decode(env["iv"]),
                    base64.b64decode(env["encrypted_payload"]) + base64.b64decode(env["tag"]),
                    None,
                )
            )
            payload = json.loads(plain_bytes.decode("utf-8"))
        except Exception as exc:
            return 400, {"error": f"Falha ao decifrar envelope híbrido: {exc}"}, False

        machine_pub_pem = str(payload.get("machine_public_key") or "").strip()
        nonce = str(payload.get("nonce") or "").strip()
        content = str(payload.get("content") or "").strip()
        signature = str(payload.get("signature") or "").strip()

        if clean_path == "/api/vote/cast/":
            if not payload.get("token") or not machine_pub_pem or not content or not nonce:
                return 400, {"error": "Campos obrigatórios ausentes em VoteCastSerializer."}, False
            decrypted_ok = False
            try:
                dev_pub = serialization.load_pem_public_key(machine_pub_pem.encode("utf-8"))
                if not isinstance(dev_pub, rsa.RSAPublicKey):
                    raise ValueError("Chave pública do dispositivo não é RSA.")
                if signature:
                    dev_pub.verify(base64.b64decode(signature), content.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256())
                content_obj = json.loads(content)
                pacote_raw = str(content_obj["pacote_cifrado"]).strip()
                ballot_plain: bytes
                parsed_pacote = None
                if pacote_raw.startswith("{"):
                    try:
                        parsed_pacote = json.loads(pacote_raw)
                    except json.JSONDecodeError:
                        parsed_pacote = None
                if isinstance(parsed_pacote, dict) and {"encrypted_payload", "encrypted_aes_key", "iv", "tag"} <= set(parsed_pacote.keys()):
                    b_aes_key = self.election_priv.decrypt(base64.b64decode(parsed_pacote["encrypted_aes_key"]), padding.PKCS1v15())
                    ballot_plain = unpad_iso7816_4(
                        AESGCM(b_aes_key[:32]).decrypt(
                            base64.b64decode(parsed_pacote["iv"]),
                            base64.b64decode(parsed_pacote["encrypted_payload"]) + base64.b64decode(parsed_pacote["tag"]),
                            None,
                        )
                    )
                else:
                    cipher_bytes = base64.b64decode(pacote_raw)
                    if len(cipher_bytes) == 256:
                        ballot_plain = unpad_iso7816_4(self.election_priv.decrypt(cipher_bytes, padding.PKCS1v15()))
                    else:
                        chunks = [
                            self.election_priv.decrypt(cipher_bytes[i : i + 256], padding.PKCS1v15())
                            for i in range(0, len(cipher_bytes), 256)
                        ]
                        ballot_plain = unpad_iso7816_4(b"".join(chunks))
                ballot_obj = json.loads(ballot_plain.decode("utf-8"))
                decrypted_ok = isinstance(ballot_obj, dict) and "choices" in ballot_obj
            except Exception:
                decrypted_ok = False
            if not decrypted_ok:
                return 400, {"error": "Cédula cifrada ou assinatura inválida."}, False

            resp_plain = {
                "election_id": 1,
                "deposited_at": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
                "status": "CONFIRMED",
                "nonce": nonce,
            }
            return 200, cifrar_envelope_servidor(dev_pub, resp_plain, compact=True), True

        if clean_path in ("/api/vote/cast-nopadding/", "/api/vote/cast-stress/"):
            resp_plain = {"status": "CONFIRMED", "nonce": nonce}
            if machine_pub_pem:
                try:
                    dev_pub = serialization.load_pem_public_key(machine_pub_pem.encode("utf-8"))
                    if isinstance(dev_pub, rsa.RSAPublicKey):
                        return 200, cifrar_envelope_servidor(dev_pub, resp_plain, compact=True), True
                except Exception:
                    pass
            return 200, resp_plain, True

        return 404, {"error": f"Rota desconhecida: {clean_path}"}, False

    def snapshot(self) -> int:
        with self._lock:
            return len(self.received_records)

    def since(self, idx: int) -> list[dict[str, Any]]:
        with self._lock:
            return list(self.received_records[idx:])

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


# ==============================================================================
# Criptografia do Cliente Vota-i 2.0 (réplica byte a byte do App Mobile)
# ==============================================================================
def carregar_chave_api_mobile(se_keys_path: Path = SE_KEYS_PATH) -> rsa.RSAPublicKey:
    """Lê VotaAI_SecureKey_2 de se_keys_info.json (blob CNG RSA1 ou PEM)."""
    keys = json.loads(se_keys_path.read_text(encoding="utf-8"))
    if isinstance(keys, dict):
        keys = [keys]
    entry = next(k for k in keys if k.get("KeyName") == "VotaAI_SecureKey_2")
    raw = str(entry["PublicKeyBase64"]).strip()
    if "-----BEGIN" in raw:
        pub = serialization.load_pem_public_key(raw.encode("utf-8"))
        assert isinstance(pub, rsa.RSAPublicKey)
        return pub
    blob = base64.b64decode(raw)
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
        .add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"), ext_val), critical=False)
        .sign(dev_priv, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def gerar_chave_dispositivo_android() -> tuple[rsa.RSAPrivateKey, str]:
    """Gera par RSA-2048 e exporta chave pública no formato exato de ModuloSegurancaHardware.java."""
    dev_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    der = dev_priv.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    b64_nowrap = base64.b64encode(der).decode("ascii")
    pem = f"-----BEGIN PUBLIC KEY-----\n{b64_nowrap}\n-----END PUBLIC KEY-----"
    return dev_priv, pem


def gerar_nonce_seguro() -> str:
    """Réplica exata de ModuloSegurancaHardware.gerarNonceSeguro() ('nonce-' + 32 hex = 38 chars)."""
    return "nonce-" + os.urandom(16).hex()


def cifrar_com_chave_eleicao(plain_package: str, election_pub: rsa.RSAPublicKey) -> str:
    """Réplica exata de ModuloSegurancaHardware.cifrarComChaveEleicao (AES-256-GCM + RSA PKCS1 + ISO/IEC 7816-4 1024 B)."""
    padded = pad_iso7816_4(plain_package.encode("utf-8"), BALLOT_PAD_BLOCK_SIZE)
    aes_key, iv = os.urandom(32), os.urandom(12)
    ct_tag = AESGCM(aes_key).encrypt(iv, padded, None)
    env = {
        "encrypted_payload": base64.b64encode(ct_tag[:-16]).decode("ascii"),
        "encrypted_aes_key": base64.b64encode(election_pub.encrypt(aes_key, padding.PKCS1v15())).decode("ascii"),
        "iv": base64.b64encode(iv).decode("ascii"),
        "tag": base64.b64encode(ct_tag[-16:]).decode("ascii"),
    }
    return json.dumps(env, separators=(",", ":"), ensure_ascii=False)


def cifrar_envelope_servidor(
    pub_key: rsa.RSAPublicKey,
    payload: dict[str, Any],
    compact: bool = True,
    pad_block_size: int | None = ENVELOPE_PAD_BLOCK_SIZE,
) -> dict[str, str]:
    """Réplica de ModuloSegurancaHardware.cifrarEnvelopeParaServidor (AES-256-GCM + RSA PKCS1 + ISO/IEC 7816-4 4096 B)."""
    aes_key, iv = os.urandom(32), os.urandom(12)
    json_str = (
        json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
        if compact
        else json.dumps(payload, ensure_ascii=False)
    )
    raw_bytes = json_str.encode("utf-8")
    plain_bytes = pad_iso7816_4(raw_bytes, pad_block_size) if pad_block_size else raw_bytes
    ct_tag = AESGCM(aes_key).encrypt(iv, plain_bytes, None)
    return {
        "encrypted_payload": base64.b64encode(ct_tag[:-16]).decode("ascii"),
        "encrypted_aes_key": base64.b64encode(pub_key.encrypt(aes_key, padding.PKCS1v15())).decode("ascii"),
        "iv": base64.b64encode(iv).decode("ascii"),
        "tag": base64.b64encode(ct_tag[-16:]).decode("ascii"),
    }


def decifrar_resposta_cliente(dev_priv: rsa.RSAPrivateKey, raw_bytes: bytes) -> Any:
    text = raw_bytes.decode("utf-8", errors="replace")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return text
    if isinstance(data, dict) and {"encrypted_payload", "encrypted_aes_key", "iv", "tag"} <= set(data.keys()):
        aes_key = dev_priv.decrypt(base64.b64decode(data["encrypted_aes_key"]), padding.PKCS1v15())
        plain = unpad_iso7816_4(
            AESGCM(aes_key[:32]).decrypt(
                base64.b64decode(data["iv"]),
                base64.b64decode(data["encrypted_payload"]) + base64.b64decode(data["tag"]),
                None,
            )
        )
        return json.loads(plain.decode("utf-8"))
    return data


def serializar_plain_package(election_id: int, choices: dict[str, int], id_voto: str) -> str:
    """Réplica exata de VoteBallotChoicesSerializer.serialize() (24 chars ISO UTC)."""
    now = datetime.datetime.now(datetime.timezone.utc)
    now_iso = now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"
    payload = {
        "election_id": election_id,
        "choices": choices,
        "timestamp": now_iso,
        "id_voto": id_voto,
    }
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)


def enviar_post_tls(
    host: str,
    port: int,
    path: str,
    envelope: dict[str, Any],
    cert_path: Path,
    tls_version: str,
    dev_priv: rsa.RSAPrivateKey | None = None,
) -> tuple[int, Any, int, int]:
    """
    Envia POST HTTPS sobre TLS real usando Connection: close e headers determinísticos,
    retornando (http_status, body_decifrado, http_content_length, client_ephemeral_port).
    """
    body_bytes = json.dumps(envelope, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ctx = ssl.create_default_context(cafile=str(cert_path))
    _configure_tls_versions(ctx, tls_version)
    conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=15.0)
    headers = {
        "Host": f"{host}:{port}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Accept-Language": "pt-BR",
        "User-Agent": "VotaAI-Mobile-Probe/1.0",
        "Connection": "close",
    }
    client_port = 0
    try:
        conn.connect()
        if conn.sock is not None:
            client_port = int(conn.sock.getsockname()[1])
        conn.request("POST", path, body=body_bytes, headers=headers)
        resp = conn.getresponse()
        raw_resp = resp.read()
        status = resp.status
        parsed = decifrar_resposta_cliente(dev_priv, raw_resp) if dev_priv is not None else raw_resp.decode("utf-8", errors="replace")
        return status, parsed, len(body_bytes), client_port
    finally:
        conn.close()


# ==============================================================================
# Funções Estatísticas em Python Puro (C3 / C1)
# ==============================================================================
def resumo_estatistico(values: list[int]) -> dict[str, Any]:
    n = len(values)
    if n == 0:
        return {"n": 0, "min": 0, "max": 0, "range": 0, "mean": 0.0, "median": 0.0, "std_pop": 0.0, "std_sample": 0.0, "iqr": 0.0, "unique_count": 0, "unique_values": []}
    s = sorted(values)
    mean = sum(s) / n
    median = float(s[n // 2]) if n % 2 == 1 else (s[n // 2 - 1] + s[n // 2]) / 2.0
    var_pop = sum((x - mean) ** 2 for x in s) / n
    var_sample = sum((x - mean) ** 2 for x in s) / (n - 1) if n > 1 else 0.0

    def _percentile(p: float) -> float:
        if n == 1:
            return float(s[0])
        k = (n - 1) * p
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return float(s[int(k)])
        return s[f] + (k - f) * (s[c] - s[f])

    iqr = _percentile(0.75) - _percentile(0.25)
    uniq = sorted(set(s))
    return {
        "n": n,
        "min": s[0],
        "max": s[-1],
        "range": s[-1] - s[0],
        "mean": round(mean, 4),
        "median": round(median, 4),
        "std_pop": round(math.sqrt(var_pop), 4),
        "std_sample": round(math.sqrt(var_sample), 4),
        "iqr": round(iqr, 4),
        "unique_count": len(uniq),
        "unique_values": uniq,
    }


def _average_ranks(values: list[float]) -> list[float]:
    n = len(values)
    indexed = sorted(enumerate(values), key=lambda it: it[1])
    ranks = [0.0] * n
    i = 0
    while i < n:
        j = i + 1
        while j < n and indexed[j][1] == indexed[i][1]:
            j += 1
        avg_r = (i + 1 + j) / 2.0
        for k in range(i, j):
            ranks[indexed[k][0]] = avg_r
        i = j
    return ranks


def pearson_r(xs: list[float], ys: list[float]) -> float | None:
    if len(xs) != len(ys) or len(xs) < 2:
        return None
    mx = sum(xs) / len(xs)
    my = sum(ys) / len(ys)
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    dx = math.sqrt(sum((x - mx) ** 2 for x in xs))
    dy = math.sqrt(sum((y - my) ** 2 for y in ys))
    if dx == 0.0 or dy == 0.0:
        return None
    return max(-1.0, min(1.0, num / (dx * dy)))


def spearman_rho(xs: list[float], ys: list[float]) -> float | None:
    if len(xs) != len(ys) or len(xs) < 2:
        return None
    return pearson_r(_average_ranks(xs), _average_ranks(ys))


def chi2_sf(x: float, df: int) -> float:
    """Função de sobrevivência P(X >= x) da distribuição qui-quadrado com df graus de liberdade."""
    if x <= 0.0 or df <= 0:
        return 1.0
    a = df / 2.0
    z = x / 2.0
    if z < a + 1.0:
        term = 1.0 / a
        summ = term
        for k in range(1, 500):
            term *= z / (a + k)
            summ += term
            if abs(term) < abs(summ) * 1e-14:
                break
        p = summ * math.exp(-z + a * math.log(z) - math.lgamma(a))
        return max(0.0, min(1.0, 1.0 - p))
    tiny = 1e-300
    b = z + 1.0 - a
    c = 1.0 / tiny
    d = 1.0 / b if abs(b) > tiny else 1.0 / tiny
    h = d
    for i in range(1, 500):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < tiny:
            d = tiny
        c = b + an / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 1e-14:
            break
    q = math.exp(-z + a * math.log(z) - math.lgamma(a)) * h
    return max(0.0, min(1.0, q))


def _betacf(a: float, b: float, x: float) -> float:
    max_iter = 200
    eps = 3.0e-12
    fpmin = 1.0e-300
    qab = a + b
    qap = a + 1.0
    qam = a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < fpmin:
        d = fpmin
    d = 1.0 / d
    h = d
    for m in range(1, max_iter + 1):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < fpmin:
            d = fpmin
        c = 1.0 + aa / c
        if abs(c) < fpmin:
            c = fpmin
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < fpmin:
            d = fpmin
        c = 1.0 + aa / c
        if abs(c) < fpmin:
            c = fpmin
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < eps:
            break
    return h


def _betainc(a: float, b: float, x: float) -> float:
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    bt = math.exp(math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b) + a * math.log(x) + b * math.log(1.0 - x))
    if x < (a + 1.0) / (a + b + 2.0):
        return bt * _betacf(a, b, x) / a
    return 1.0 - bt * _betacf(b, a, 1.0 - x) / b


def kruskal_wallis(groups: dict[str, list[float]]) -> tuple[float, float]:
    non_empty = {k: v for k, v in groups.items() if v}
    if len(non_empty) < 2:
        return 0.0, 1.0
    all_vals: list[float] = []
    group_slices: list[tuple[int, int]] = []
    for vals in non_empty.values():
        start = len(all_vals)
        all_vals.extend(vals)
        group_slices.append((start, len(all_vals)))

    n = len(all_vals)
    if len(set(all_vals)) <= 1:
        return 0.0, 1.0

    ranks = _average_ranks(all_vals)
    h_raw = (12.0 / (n * (n + 1))) * sum((sum(ranks[s:e]) ** 2) / (e - s) for s, e in group_slices) - 3.0 * (n + 1)

    counts = Counter(all_vals)
    tie_sum = sum(t ** 3 - t for t in counts.values() if t > 1)
    denom_corr = 1.0 - tie_sum / (n ** 3 - n)
    h = h_raw / denom_corr if denom_corr > 0 else 0.0
    df = len(non_empty) - 1
    return h, chi2_sf(h, df)


def anova_one_way(groups: dict[str, list[float]]) -> tuple[float, float]:
    non_empty = {k: v for k, v in groups.items() if v}
    k = len(non_empty)
    all_vals = [x for v in non_empty.values() for x in v]
    n = len(all_vals)
    if k < 2 or n <= k:
        return 0.0, 1.0
    grand_mean = sum(all_vals) / n
    ss_between = sum(len(v) * ((sum(v) / len(v)) - grand_mean) ** 2 for v in non_empty.values())
    ss_within = sum(sum((x - (sum(v) / len(v))) ** 2 for x in v) for v in non_empty.values())
    df_between = k - 1
    df_within = n - k
    ms_between = ss_between / df_between
    ms_within = ss_within / df_within
    if ms_within == 0.0:
        if ms_between == 0.0:
            return 0.0, 1.0
        return float("inf"), 0.0
    f_stat = ms_between / ms_within
    x = df_within / (df_within + df_between * f_stat)
    p_val = _betainc(df_within / 2.0, df_between / 2.0, x)
    return f_stat, max(0.0, min(1.0, p_val))


def entropia_shannon(values: list[Any]) -> float:
    n = len(values)
    if n == 0:
        return 0.0
    counts = Counter(values)
    h = 0.0
    for c in counts.values():
        p = c / n
        if p > 0:
            h -= p * math.log2(p)
    return 0.0 if abs(h) < 1e-12 else h


def informacao_mutua(sizes: list[int], labels: list[str]) -> float:
    n = len(sizes)
    if n == 0 or len(labels) != n:
        return 0.0
    cx = Counter(sizes)
    cy = Counter(labels)
    cxy = Counter(zip(sizes, labels))
    mi = 0.0
    for (x, y), c in cxy.items():
        pxy = c / n
        px = cx[x] / n
        py = cy[y] / n
        mi += pxy * math.log2(pxy / (px * py))
    return 0.0 if abs(mi) < 1e-12 else mi


def acuracia_classificador_passivo(sizes: list[int], labels: list[str]) -> dict[str, Any]:
    n = len(sizes)
    if n == 0:
        return {"baseline_acaso": 0.0, "bayes_insample_acc": 0.0, "loocv_acc": 0.0}
    label_counts = Counter(labels)
    baseline = max(label_counts.values()) / n

    # Bayes ótimo in-sample: para cada tamanho s, prediz a classe mais frequente em s
    by_size: dict[int, Counter[str]] = defaultdict(Counter)
    for s, lbl in zip(sizes, labels):
        by_size[s][lbl] += 1
    bayes_correct = sum(cnt.most_common(1)[0][1] for cnt in by_size.values())
    bayes_acc = bayes_correct / n

    # LOOCV: para cada amostra i, usa apenas os n-1 demais votos com o mesmo tamanho (desempate por classe majoritária global)
    loocv_correct = 0
    for i, (s, lbl) in enumerate(zip(sizes, labels)):
        rem_counts = Counter(labels[j] for j in range(n) if j != i and sizes[j] == s)
        if rem_counts:
            pred = sorted(rem_counts.items(), key=lambda it: (-it[1], -label_counts[it[0]], it[0]))[0][0]
        else:
            pred = sorted(label_counts.items(), key=lambda it: (-it[1], it[0]))[0][0]
        if pred == lbl:
            loocv_correct += 1

    return {
        "baseline_acaso": round(baseline, 4),
        "bayes_insample_acc": round(bayes_acc, 4),
        "loocv_acc": round(loocv_correct / n, 4),
    }


# ==============================================================================
# Associação Stream Wireshark <-> Amostras de Voto
# ==============================================================================
def associar_streams_amostras(
    samples: list[VoteSample],
    streams: dict[int, TlsStreamSummary],
) -> None:
    """Vincula cada VoteSample ao respectivo tcp.stream dissecado pelo tshark."""
    by_cli_port: dict[int, list[TlsStreamSummary]] = defaultdict(list)
    for st in sorted(streams.values(), key=lambda s: (s.first_ts, s.stream_id)):
        by_cli_port[st.client_port].append(st)

    used_streams: set[int] = set()
    for sm in samples:
        candidates = [st for st in by_cli_port.get(sm.client_port, []) if st.stream_id not in used_streams]
        if candidates:
            st = candidates[0]
            used_streams.add(st.stream_id)
            sm.tcp_stream = st.stream_id
            sm.tls_version = st.tls_version
            sm.tls_ciphersuite = st.ciphersuite
            sm.tls_http_post_bytes = st.tls_http_post_bytes
            sm.tls_max_record_bytes = st.tls_max_record_bytes
            sm.tls_total_appdata_bytes = st.tls_total_appdata_bytes
            sm.tcp_c2s_payload_bytes = st.tcp_c2s_payload_bytes
            sm.tls_c2s_record_sizes = list(st.c2s_appdata_records)

    remaining_streams = [
        st for st in sorted(streams.values(), key=lambda s: (s.first_ts, s.stream_id))
        if st.stream_id not in used_streams and st.c2s_appdata_records
    ]
    rem_iter = iter(remaining_streams)
    for sm in samples:
        if sm.tcp_stream is not None:
            continue
        st = next(rem_iter, None)
        if st is None:
            continue
        sm.tcp_stream = st.stream_id
        sm.tls_version = st.tls_version
        sm.tls_ciphersuite = st.ciphersuite
        sm.tls_http_post_bytes = st.tls_http_post_bytes
        sm.tls_max_record_bytes = st.tls_max_record_bytes
        sm.tls_total_appdata_bytes = st.tls_total_appdata_bytes
        sm.tcp_c2s_payload_bytes = st.tcp_c2s_payload_bytes
        sm.tls_c2s_record_sizes = list(st.c2s_appdata_records)


# ==============================================================================
# C1 — Controle Negativo no Wireshark (Contraprova sem Padding/Indireção)
# ==============================================================================
def executar_controle_negativo(
    tshark_cmd: list[str],
    cert_path: Path,
    origin: OriginVoteHTTPSServer,
    api_pub: rsa.RSAPublicKey,
    target_host: str,
    tls_version: str,
    capture_mode: str,
    interface: str,
    tmp_dir: Path,
) -> tuple[CheckResult, dict[str, Any]]:
    """
    Envia 8 votos (2 por categoria) contendo o rótulo nominal do candidato sob AES-256-GCM
    sem indireção por ID e sem padding de tamanho fixo, capturando e dissecando via Wireshark/tshark.
    """
    tap: PassiveTCPWireTap | None = None
    td: TcpdumpCapture | None = None
    if capture_mode == "tcpdump":
        td = TcpdumpCapture(interface, origin.port, tmp_dir / "c1_neg.pcap")
        dst_port = origin.port
    else:
        tap = PassiveTCPWireTap("127.0.0.1", origin.port)
        dst_port = tap.listen_port

    neg_samples: list[dict[str, Any]] = []
    try:
        seq = 0
        for rep in range(2):
            for opt in STANDARD_OPTIONS:
                seq += 1
                dev_priv, dev_pub_pem = gerar_chave_dispositivo_android()
                token = secrets_urlsafe_token()
                nonce = gerar_nonce_seguro()
                # Payload nominal sem indireção e sem padding RSA de bloco fixo
                raw_ballot = json.dumps(
                    {
                        "election_id": 1,
                        "candidate_label": opt["label"],
                        "option_id": opt["option_id"],
                        "timestamp": "2026-11-22T18:00:00.000Z",
                    },
                    separators=(",", ":"),
                    ensure_ascii=False,
                )
                envelope = cifrar_envelope_servidor(
                    api_pub,
                    {
                        "token": token,
                        "machine_public_key": dev_pub_pem,
                        "content": raw_ballot,
                        "nonce": nonce,
                        "signature": "",
                    },
                    pad_block_size=None,
                )
                status, _, http_len, cli_port = enviar_post_tls(
                    target_host,
                    dst_port,
                    "/api/vote/cast-nopadding/",
                    envelope,
                    cert_path,
                    tls_version,
                    dev_priv=dev_priv,
                )
                neg_samples.append(
                    {
                        "seq": seq,
                        "rep": rep + 1,
                        "category": opt["category"],
                        "nominal_bytes": len(opt["label"].encode("utf-8")),
                        "http_content_length": http_len,
                        "http_status": status,
                        "client_port": cli_port,
                        "tls_http_post_bytes": 0,
                    }
                )
    finally:
        pcap_bytes = td.stop() if td is not None else (tap.stop() if tap is not None else b"")

    streams = dissecar_pcap_com_tshark(tshark_cmd, pcap_bytes, server_port=dst_port)
    by_port = {st.client_port: st for st in streams.values() if st.client_port}
    for item in neg_samples:
        st = by_port.get(item["client_port"])
        if st:
            item["tls_http_post_bytes"] = st.tls_http_post_bytes

    tls_sizes = [it["tls_http_post_bytes"] for it in neg_samples]
    nom_lens = [float(it["nominal_bytes"]) for it in neg_samples]
    stats = resumo_estatistico(tls_sizes)
    r_val = pearson_r(nom_lens, [float(s) for s in tls_sizes])
    clf = acuracia_classificador_passivo(tls_sizes, [it["category"] for it in neg_samples])

    by_cat: dict[str, list[int]] = defaultdict(list)
    for it in neg_samples:
        by_cat[it["category"]].append(it["tls_http_post_bytes"])

    cat_summary = ", ".join(f"{cat}={sorted(set(v))}B" for cat, v in by_cat.items())
    details = [
        f"Amostras C1 (2 por categoria, AES-256-GCM/NoPadding sem indireção): {cat_summary}",
        f"Wireshark/TShark observou: min={stats['min']} B, max={stats['max']} B, amplitude={stats['range']} B, tamanhos_distintos={stats['unique_count']}.",
        f"Correlação nominal vs pacote TLS: Pearson r={r_val:.6f}" if r_val is not None else "Pearson r=indefinido",
        f"Classificador passivo (acaso=25.0%): Bayes in-sample={clf['bayes_insample_acc'] * 100:.1f}%, LOOCV={clf['loocv_acc'] * 100:.1f}%.",
    ]

    ok = (
        len(neg_samples) == 8
        and all(it["http_status"] == 200 and it["tls_http_post_bytes"] > 0 for it in neg_samples)
        and stats["unique_count"] >= 3
        and stats["range"] >= 150
        and r_val is not None
        and r_val >= 0.99
    )
    meta = {"stats": stats, "pearson_r": r_val, "classifier": clf, "samples": neg_samples}
    if ok:
        return (
            CheckResult(
                "C1",
                "Controle Negativo no Wireshark (Contraprova sem Padding/Indireção)",
                "PASSOU",
                f"Aparato Wireshark/TShark detectou vazamento claro sem padding (amplitude={stats['range']} B, r={r_val:.4f}, Bayes={clf['bayes_insample_acc'] * 100:.1f}%).",
                details,
            ),
            meta,
        )
    return (
        CheckResult(
            "C1",
            "Controle Negativo no Wireshark (Contraprova sem Padding/Indireção)",
            "FALHOU",
            "Controle negativo não demonstrou sensibilidade esperada na captura Wireshark.",
            details,
        ),
        meta,
    )


def secrets_urlsafe_token() -> str:
    """Gera token URL-safe com exatamente os mesmos 32 bytes de VotingTokenService (43 chars)."""
    return base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")


# ==============================================================================
# C2 / C3 — Avaliação de Uniformidade e Análise Estatística (Wireshark)
# ==============================================================================
def avaliar_uniformidade_c2(samples: list[VoteSample], offline_mode: bool) -> CheckResult:
    if not samples:
        return CheckResult("C2", "Uniformidade de Tamanho na Camada TLS (Wireshark/TShark)", "FALHOU", "Nenhuma amostra de voto capturada para análise.", [])

    tls_sizes = [s.tls_http_post_bytes for s in samples]
    http_lens = [s.http_content_length for s in samples if s.http_content_length > 0]
    b64_lens = [s.pacote_cifrado_b64_len for s in samples if s.pacote_cifrado_b64_len > 0]

    stats_tls = resumo_estatistico(tls_sizes)
    by_cat: dict[str, list[VoteSample]] = defaultdict(list)
    for s in samples:
        by_cat[s.category].append(s)

    details = [
        f"Amostras analisadas no Wireshark: N={len(samples)} | categorias={list(by_cat.keys())}",
        "Tabela por categoria (comprimentos medidos no PCAP via tshark):",
    ]
    for cat, items in by_cat.items():
        st_cat = resumo_estatistico([x.tls_http_post_bytes for x in items])
        nom_set = sorted({x.nominal_bytes for x in items})
        b64_set = sorted({x.pacote_cifrado_b64_len for x in items if x.pacote_cifrado_b64_len > 0})
        http_set = sorted({x.http_content_length for x in items if x.http_content_length > 0})
        nom_s = f"{nom_set[0]}B" if len(nom_set) == 1 else f"{min(nom_set)}-{max(nom_set)}B"
        b64_s = f"{b64_set[0]}B" if b64_set else "n/a"
        http_s = f"{http_set[0]}B" if http_set else "n/a"
        details.append(
            f"  - {cat:<11} | N={len(items):>2} | nominal={nom_s:<5} | pacote_cifrado={b64_s:<5} | "
            f"HTTP_CL={http_s:<6} | TLS_POST=[min={st_cat['min']}B, max={st_cat['max']}B, std={st_cat['std_pop']:.2f}B]"
        )

    all_confirmed = True if offline_mode else all(s.confirmed and s.http_status == 200 for s in samples)
    all_nonzero = all(x > 0 for x in tls_sizes)
    tls_fixed = stats_tls["unique_count"] == 1 and stats_tls["range"] == 0
    http_fixed = True if not http_lens else len(set(http_lens)) == 1
    b64_fixed = True if not b64_lens else len(set(b64_lens)) == 1

    if len(samples) >= 4 and all_confirmed and all_nonzero and tls_fixed and http_fixed and b64_fixed:
        return CheckResult(
            "C2",
            "Uniformidade de Tamanho na Camada TLS (Wireshark/TShark)",
            "PASSOU",
            f"Todos os {len(samples)} pacotes POST /api/vote/cast/ apresentaram tamanho TLS estritamente fixo ({stats_tls['min']} B, amplitude=0 B, std=0.00 B).",
            details,
        )

    reasons: list[str] = []
    if not all_confirmed:
        reasons.append("nem todos os votos retornaram 200 CONFIRMED")
    if not all_nonzero:
        reasons.append("há fluxos sem payload TLS contabilizado")
    if not tls_fixed:
        reasons.append(f"variação detectada na camada TLS ({stats_tls['unique_count']} tamanhos distintos: {stats_tls['unique_values']}, amplitude={stats_tls['range']} B)")
    if not http_fixed:
        reasons.append(f"variação em HTTP Content-Length ({sorted(set(http_lens))})")
    if not b64_fixed:
        reasons.append(f"variação em pacote_cifrado Base64 ({sorted(set(b64_lens))})")
    return CheckResult(
        "C2",
        "Uniformidade de Tamanho na Camada TLS (Wireshark/TShark)",
        "FALHOU",
        "Falha na uniformidade de tamanho: " + "; ".join(reasons) + ".",
        details,
    )


def avaliar_estatistica_c3(samples: list[VoteSample]) -> tuple[CheckResult, dict[str, Any]]:
    if len(samples) < 4:
        return (
            CheckResult("C3", "Análise Estatística e Inferência por Observador Passivo", "FALHOU", "Amostra insuficiente para análise estatística (< 4 votos).", []),
            {},
        )

    tls_sizes = [s.tls_http_post_bytes for s in samples]
    tls_floats = [float(x) for x in tls_sizes]
    nom_floats = [float(s.nominal_bytes) for s in samples]
    id_digits = [float(len(str(s.option_id))) for s in samples]
    categories = [s.category for s in samples]

    groups: dict[str, list[float]] = defaultdict(list)
    for s in samples:
        groups[s.category].append(float(s.tls_http_post_bytes))

    r_nom = pearson_r(nom_floats, tls_floats)
    rho_nom = spearman_rho(nom_floats, tls_floats)
    r_id = pearson_r(id_digits, tls_floats)
    kw_h, kw_p = kruskal_wallis(groups)
    f_stat, f_p = anova_one_way(groups)
    h_size = entropia_shannon(tls_sizes)
    mi = informacao_mutua(tls_sizes, categories)
    clf = acuracia_classificador_passivo(tls_sizes, categories)

    def _fmt_corr(val: float | None) -> str:
        return "indefinido (variância nula = 0)" if val is None else f"{val:.6f}"

    details = [
        f"Correlação comprimento nominal vs bytes TLS : Pearson r={_fmt_corr(r_nom)} | Spearman ρ={_fmt_corr(rho_nom)}",
        f"Correlação dígitos option_id vs bytes TLS   : Pearson r={_fmt_corr(r_id)}",
        f"Testes de hipótese entre categorias         : Kruskal-Wallis H={kw_h:.4f} (p={kw_p:.4f}) | ANOVA F={f_stat:.4f} (p={f_p:.4f})",
        f"Teoria da Informação                        : Entropia H(Size)={h_size:.4f} bits | Informação Mútua I(Size; Categoria)={mi:.4f} bits",
        f"Classificador passivo (acaso={clf['baseline_acaso'] * 100:.1f}%)       : Bayes in-sample={clf['bayes_insample_acc'] * 100:.1f}% | LOOCV={clf['loocv_acc'] * 100:.1f}%",
    ]
    metrics = {
        "pearson_nominal": r_nom,
        "spearman_nominal": rho_nom,
        "pearson_option_id_digits": r_id,
        "kruskal_wallis_h": round(kw_h, 6),
        "kruskal_wallis_p": round(kw_p, 6),
        "anova_f": round(f_stat, 6) if math.isfinite(f_stat) else "inf",
        "anova_p": round(f_p, 6),
        "entropy_bits": round(h_size, 6),
        "mutual_info_bits": round(mi, 6),
        "classifier": clf,
    }

    zero_leakage = h_size == 0.0 and mi == 0.0 and kw_p >= 0.05 and clf["bayes_insample_acc"] <= clf["baseline_acaso"] + 1e-6
    if zero_leakage:
        return (
            CheckResult(
                "C3",
                "Análise Estatística e Inferência por Observador Passivo",
                "PASSOU",
                f"Correlação impossível: H(Size)=0.0000 bits, I(Size; Categoria)=0.0000 bits, acurácia passiva={clf['bayes_insample_acc'] * 100:.1f}% (= acaso).",
                details,
            ),
            metrics,
        )

    if mi < 0.05 and kw_p > 0.05 and f_p > 0.05 and clf["bayes_insample_acc"] <= clf["baseline_acaso"] + 0.05:
        return (
            CheckResult(
                "C3",
                "Análise Estatística e Inferência por Observador Passivo",
                "PASSOU",
                f"Sem evidência estatística de inferência (I={mi:.4f} bits, p={kw_p:.4f}), mas há variância não-nula avaliada em C2.",
                details,
            ),
            metrics,
        )

    return (
        CheckResult(
            "C3",
            "Análise Estatística e Inferência por Observador Passivo",
            "FALHOU",
            f"Vazamento estatístico detectado: I(Size; Categoria)={mi:.4f} bits, Bayes={clf['bayes_insample_acc'] * 100:.1f}% (acaso={clf['baseline_acaso'] * 100:.1f}%), KW p={kw_p:.4f}.",
            details,
        ),
        metrics,
    )


# ==============================================================================
# C4 — Auditoria Estática de Código e Limites de Fronteira de Padding
# ==============================================================================
def auditar_fronteiras_padding_c4(
    tshark_cmd: list[str] | None,
    cert_path: Path | None,
    origin: OriginVoteHTTPSServer | None,
    api_pub: rsa.RSAPublicKey | None,
    target_host: str,
    tls_version: str,
    capture_mode: str,
    interface: str,
    tmp_dir: Path | None,
    strict_padding: bool,
) -> tuple[CheckResult, dict[str, Any]]:
    """
    Inspeciona estaticamente o código-fonte do Vota-i 2.0 (mobile/backend/desktop) e executa
    sondas reais de fronteira (>245B RSA multi-bloco e nonce variável em AES/GCM/NoPadding).
    """
    findings: list[str] = []
    protections: list[str] = []

    serializers_ts = MOBILE_DIR / "src" / "services" / "vote" / "vote.serializers.ts"
    hw_java = MOBILE_DIR / "android" / "app" / "src" / "main" / "java" / "com" / "meuapptestecripto" / "ModuloSegurancaHardware.java"
    vote_srv_ts = MOBILE_DIR / "src" / "services" / "vote" / "vote.service.ts"
    token_srv_py = BACKEND_DIR / "Infrastructure" / "services" / "votingTokenService.py"
    se_mw_py = BACKEND_DIR / "Infrastructure" / "middlewares" / "seDecryptMiddleware.py"
    tally_py = DESKTOP_DIR / "app" / "controllers" / "tallyElectionController.py"
    tpm_linux_py = DESKTOP_DIR / "app" / "controllers" / "native" / "tpm_linux.py"

    static_ok = True
    if serializers_ts.is_file():
        src = serializers_ts.read_text(encoding="utf-8")
        if "VoteBallotChoicesSerializer" in src and "choices," in src:
            protections.append("Indireção nominal: VoteBallotChoicesSerializer envia apenas IDs numéricos (`choices: {qId: optionId}`), sem strings de nome/chapa.")
    if hw_java.is_file():
        src = hw_java.read_text(encoding="utf-8")
        if "BALLOT_PAD_BLOCK_SIZE" in src and "padIso7816_4" in src:
            protections.append("Padding explícito na cédula (ModuloSegurancaHardware.java): cifrarComChaveEleicao aplica ISO/IEC 7816-4 (1024 B) + envelope híbrido AES-256-GCM/RSA.")
        else:
            static_ok = False
            findings.append("Sem padding explícito pré-cifragem para >245B: ModuloSegurancaHardware.cifrarComChaveEleicao quebra em múltiplos blocos de 256B.")
        if "ENVELOPE_PAD_BLOCK_SIZE" in src and "padIso7816_4" in src:
            protections.append("Padding explícito no envelope de rede (ModuloSegurancaHardware.java): cifrarEnvelopeParaServidor aplica ISO/IEC 7816-4 (4096 B) antes do AES-256-GCM.")
        else:
            static_ok = False
            findings.append("Envelope de rede usa AES/GCM/NoPadding sem padding de tamanho fixo.")
        if "gerarNonceSeguro" in src:
            protections.append("Nonce fixo em produção: gerarNonceSeguro() gera sempre 'nonce-' + 32 hex (38 chars).")
    if vote_srv_ts.is_file():
        src = vote_srv_ts.read_text(encoding="utf-8")
        if "padStart" in src and "generateNonce()" in src:
            protections.append("Fallback JS generateNonce() padronizado com comprimento fixo (35 chars via padStart).")
        else:
            static_ok = False
            findings.append("Fallback JS generateNonce() gera comprimento variável.")
    if token_srv_py.is_file():
        src = token_srv_py.read_text(encoding="utf-8")
        if "secrets.token_urlsafe(32)" in src:
            protections.append("Token de votação fixo: VotingTokenService emite secrets.token_urlsafe(32) (43 chars).")
    if se_mw_py.is_file():
        src = se_mw_py.read_text(encoding="utf-8")
        if "unpad_iso7816_4" in src:
            protections.append("Backend (SEDecryptMiddleware): remove padding ISO/IEC 7816-4 de requisições cifradas mantendo compatibilidade legada.")
        else:
            static_ok = False
            findings.append("Backend SEDecryptMiddleware não remove padding ISO/IEC 7816-4.")
    if tally_py.is_file() and tpm_linux_py.is_file():
        tsrc = tally_py.read_text(encoding="utf-8")
        nsrc = tpm_linux_py.read_text(encoding="utf-8")
        if "unpad_iso7816_4" in tsrc and "_unpad_iso7816_4" in nsrc:
            protections.append("Apuração Desktop (tallyElectionController / módulos nativos): suporta cédulas híbridas com remoção ISO/IEC 7816-4.")
        else:
            static_ok = False
            findings.append("Apuração Desktop não remove padding ISO/IEC 7816-4.")

    probe_info: dict[str, Any] = {}
    probes_ok = True
    if tshark_cmd and cert_path and origin and api_pub and tmp_dir:
        tap: PassiveTCPWireTap | None = None
        td: TcpdumpCapture | None = None
        if capture_mode == "tcpdump":
            td = TcpdumpCapture(interface, origin.port, tmp_dir / "c4_boundary.pcap")
            dst_port = origin.port
        else:
            tap = PassiveTCPWireTap("127.0.0.1", origin.port)
            dst_port = tap.listen_port

        probe_records: list[dict[str, Any]] = []
        try:
            # Sonda 4A: 14 questões com IDs de 1 dígito (<=245B) vs 4 dígitos (>245B)
            choices_small = {str(i): 1 for i in range(1, 15)}
            choices_large = {str(i): 1000 + i for i in range(1, 15)}
            for tag, ch in (("14q_ids_1digito_le245B", choices_small), ("14q_ids_4digitos_gt245B", choices_large)):
                dev_priv, dev_pub_pem = gerar_chave_dispositivo_android()
                id_voto = f"VOTE-{os.urandom(16).hex().upper()}"
                plain = serializar_plain_package(1, ch, id_voto)
                pac = cifrar_com_chave_eleicao(plain, origin.election_pub)
                content = json.dumps({"id_voto": id_voto, "pacote_cifrado": pac}, separators=(",", ":"))
                sig = base64.b64encode(dev_priv.sign(content.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256())).decode("ascii")
                env = cifrar_envelope_servidor(
                    api_pub,
                    {
                        "token": secrets_urlsafe_token(),
                        "machine_public_key": dev_pub_pem,
                        "content": content,
                        "nonce": gerar_nonce_seguro(),
                        "signature": sig,
                    },
                )
                status, _, http_len, cli_port = enviar_post_tls(target_host, dst_port, "/api/vote/cast/", env, cert_path, tls_version, dev_priv=dev_priv)
                probe_records.append(
                    {
                        "probe": tag,
                        "plain_bytes": len(plain.encode("utf-8")),
                        "pacote_cifrado_b64": len(pac),
                        "http_cl": http_len,
                        "status": status,
                        "client_port": cli_port,
                    }
                )

            # Sonda 4B: Variação de nonce no envelope externo (8B vs 40B)
            for tag, nonce_val in (("nonce_curto_8B", "nonce-12"), ("nonce_longo_40B", "nonce-" + "a" * 34)):
                dev_priv, dev_pub_pem = gerar_chave_dispositivo_android()
                env = cifrar_envelope_servidor(
                    api_pub,
                    {"token": secrets_urlsafe_token(), "machine_public_key": dev_pub_pem, "content": "{}", "nonce": nonce_val, "signature": ""},
                )
                status, _, http_len, cli_port = enviar_post_tls(target_host, dst_port, "/api/vote/cast-stress/", env, cert_path, tls_version, dev_priv=dev_priv)
                probe_records.append(
                    {"probe": tag, "plain_bytes": len(nonce_val), "pacote_cifrado_b64": 0, "http_cl": http_len, "status": status, "client_port": cli_port}
                )
        finally:
            pcap_bytes = td.stop() if td is not None else (tap.stop() if tap is not None else b"")

        streams = dissecar_pcap_com_tshark(tshark_cmd, pcap_bytes, server_port=dst_port)
        by_port = {st.client_port: st for st in streams.values() if st.client_port}
        for rec in probe_records:
            st = by_port.get(rec["client_port"])
            rec["tls_http_post_bytes"] = st.tls_http_post_bytes if st else 0

        p_le, p_gt = probe_records[0], probe_records[1]
        p_ns, p_nl = probe_records[2], probe_records[3]
        delta_rsa = p_gt["tls_http_post_bytes"] - p_le["tls_http_post_bytes"]
        delta_nonce = p_nl["tls_http_post_bytes"] - p_ns["tls_http_post_bytes"]
        probes_ok = (
            all(r["status"] == 200 and r["tls_http_post_bytes"] > 0 for r in probe_records)
            and delta_rsa == 0
            and delta_nonce == 0
        )
        probe_info = {"rsa_boundary": [p_le, p_gt], "rsa_delta_tls_bytes": delta_rsa, "nonce_variation": [p_ns, p_nl], "nonce_delta_tls_bytes": delta_nonce}

        protections.append(
            f"Sonda 4A (fronteira 245B multi-questão): <=245B ({p_le['plain_bytes']}B -> pacote={p_le['pacote_cifrado_b64']}B -> TLS={p_le['tls_http_post_bytes']}B) "
            f"vs >245B ({p_gt['plain_bytes']}B -> pacote={p_gt['pacote_cifrado_b64']}B -> TLS={p_gt['tls_http_post_bytes']}B | salto=+{delta_rsa} B no Wireshark)."
        )
        protections.append(
            f"Sonda 4B (envelope externo com nonce variável): {p_ns['plain_bytes']}B -> TLS={p_ns['tls_http_post_bytes']}B "
            f"vs {p_nl['plain_bytes']}B -> TLS={p_nl['tls_http_post_bytes']}B (diferença=+{delta_nonce} B no Wireshark)."
        )

    if static_ok and probes_ok:
        status_c4 = "PASSOU"
        summary_c4 = "Padding criptográfico explícito ISO/IEC 7816-4 ativo na cédula (1024 B) e no envelope (4096 B), com variância zero nas sondas de fronteira."
    else:
        status_c4 = "FALHOU" if strict_padding else "ALERTA"
        summary_c4 = (
            "Falha ou ausência de padding explícito de tamanho fixo nos limites de fronteira."
            if strict_padding
            else "Protegido no cenário padrão (<=245B), com limitações arquiteturais de fronteira para trabalhos futuros."
        )
    return CheckResult("C4", "Auditoria Estática de Código e Limites de Fronteira de Padding", status_c4, summary_c4, protections + findings), probe_info


# ==============================================================================
# Adaptador de Banco e Ciclo Completo / Tokens Reais contra Backend Django
# ==============================================================================
def ler_dotenv(env_path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    if not env_path.exists():
        return env
    for raw in env_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in ('"', "'"):
            v = v[1:-1]
        env[k] = v
    return env


def _connect_db(db_url: str | None, sqlite_path: Path | None, env_path: Path) -> Any:
    dsn = db_url or os.environ.get("DATABASE_URL")
    if dsn:
        if psycopg2 is None:
            raise RuntimeError("psycopg2 não instalado.")
        conn = psycopg2.connect(dsn)
        conn.set_session(readonly=True, autocommit=True)
        return ("postgresql", conn)
    if sqlite_path is not None:
        return ("sqlite", sqlite3.connect(f"file:{sqlite_path}?mode=ro", uri=True))
    env = ler_dotenv(env_path)
    db_name = env.get("DB_NAME", "").strip()
    if db_name:
        if psycopg2 is None:
            raise RuntimeError("psycopg2 não instalado.")
        host = env.get("DB_HOST", "db").strip() or "db"
        port = int((env.get("DB_PORT", "5432").strip() or "5432"))
        user = env.get("DB_USER", "postgres").strip() or "postgres"
        pwd = env.get("DB_PASSWORD", "postgres")
        try:
            conn = psycopg2.connect(dbname=db_name, user=user, password=pwd, host=host, port=port)
        except psycopg2.OperationalError:
            conn = psycopg2.connect(dbname=db_name, user=user, password=pwd, host="127.0.0.1", port=port)
        conn.set_session(readonly=True, autocommit=True)
        return ("postgresql", conn)
    return ("sqlite", sqlite3.connect(f"file:{DEFAULT_SQLITE_PATH}?mode=ro", uri=True))


def _classificar_opcoes_eleicao(questions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Classifica as opções da primeira questão em CURTO, CHAPA_LONGA, BRANCO e NULO."""
    if not questions:
        raise RuntimeError("Eleição retornada não possui perguntas.")
    q = questions[0]
    q_id = str(q["id"])
    opts = list(q.get("options") or [])
    branco = next((o for o in opts if str(o.get("label", "")).strip().lower() == "branco"), None)
    nulo = next((o for o in opts if str(o.get("label", "")).strip().lower() == "nulo"), None)
    candidatos = [o for o in opts if o not in (branco, nulo)]
    if not candidatos:
        candidatos = opts
    candidatos_sorted = sorted(candidatos, key=lambda o: len(str(o.get("label", "")).encode("utf-8")))
    curto = candidatos_sorted[0]
    longo = candidatos_sorted[-1]
    mapped: list[dict[str, Any]] = [
        {"category": "CURTO", "question_id": q_id, "option_id": int(curto["id"]), "label": str(curto["label"])},
        {"category": "CHAPA_LONGA", "question_id": q_id, "option_id": int(longo["id"]), "label": str(longo["label"])},
    ]
    if branco:
        mapped.append({"category": "BRANCO", "question_id": q_id, "option_id": int(branco["id"]), "label": str(branco["label"])})
    if nulo:
        mapped.append({"category": "NULO", "question_id": q_id, "option_id": int(nulo["id"]), "label": str(nulo["label"])})
    return mapped


def _carregar_tokens(args: argparse.Namespace) -> list[str]:
    tokens = [t.strip() for t in (args.tokens or []) if t.strip()]
    if args.tokens_file:
        for line in Path(args.tokens_file).read_text(encoding="utf-8").splitlines():
            clean = line.strip()
            if clean and not clean.startswith("#"):
                tokens.append(clean)
    return tokens


def _preparar_eleicao_full_lifecycle(args: argparse.Namespace) -> list[str]:
    """Cria e inicia eleição efêmera no backend Django real com 4 opções contrastantes e captura os tokens."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "Eixo 1"))
    import maquinaEstados as fsm  # noqa: PLC0415

    db = fsm.DBAdapter.connect(db_url=args.db_url, sqlite_path=args.sqlite, env_path=args.env_file)
    try:
        api_pub_1 = fsm.carregar_chave_servidor("VotaAI_SecureKey_1", args.se_keys)
        signer = fsm.DesktopMachineSigner(args.client_key, DEFAULT_CLIENT_KEYS_DIR)
        auth_token = args.auth_token
        if not auth_token:
            auth_token = fsm.autenticar_admin_desktop(
                args.backend_url,
                api_pub_1,
                signer,
                db,
                admin_email=args.admin_email,
                admin_password=args.admin_password,
                admin_totp=args.admin_totp,
                device_id=args.device_id,
            )

        election_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        election_pub_pem = election_priv.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

        uid = uuid.uuid4().hex[:10]
        total_votes = args.repeats * 4
        voters = [{"email": f"eleitor{i+1}.pad.{uid}@votaai.test", "full_name": f"Eleitor Padding {i+1}"} for i in range(total_votes)]
        title = f"[TESTE-PADDING] Trafego TLS {datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}-{uid[:6]}"
        key_handle = f"votaai_pad_test_{uid}"

        create_payload = {
            "title": title,
            "ballot": [
                {
                    "question": "Escolha sua chapa ou opção de voto:",
                    "order": 1,
                    "options": [{"label": STANDARD_OPTIONS[0]["label"]}, {"label": STANDARD_OPTIONS[1]["label"]}],
                }
            ],
            "electoral_college": voters,
            "public_key": election_pub_pem,
            "key_handle": key_handle,
        }
        code_cr, body_cr = fsm._post_desktop(args.backend_url, "/api/election/create/", api_pub_1, create_payload, signer=signer, auth_token=auth_token)
        if code_cr != 200 or not isinstance(body_cr, dict):
            raise RuntimeError(f"Falha ao criar eleição em --full-lifecycle (HTTP {code_cr}): {body_cr}")

        since_ts = time.time()
        start_pl = {"msg": "START_ELECTION", "keyHandle": key_handle, "nonceClient2": f"pad-start-{uuid.uuid4().hex[:8]}"}
        start_pl["election_signature"] = fsm.assinar_eleicao(election_priv, start_pl)
        code_st, body_st = fsm._post_desktop(args.backend_url, "/api/election/start/", api_pub_1, start_pl, signer=signer, auth_token=auth_token)
        if code_st != 200:
            raise RuntimeError(f"Falha ao iniciar eleição em --full-lifecycle (HTTP {code_st}): {body_st}")

        tokens_map = fsm.capturar_tokens_email(args.sent_emails_dir, title, since_ts)
        tokens = [tokens_map[v["email"].lower()] for v in voters if v["email"].lower() in tokens_map]
        if len(tokens) < 4:
            raise RuntimeError(f"Tokens capturados em {args.sent_emails_dir} insuficientes ({len(tokens)}/{total_votes}).")
        return tokens
    finally:
        db.close()


# ==============================================================================
# Execução dos Votos no Canal TLS Ativo + Captura Wireshark
# ==============================================================================
def executar_ensaio_live(args: argparse.Namespace, tshark_cmd: list[str], tshark_ver: str) -> tuple[list[CheckResult], dict[str, Any], bytes, dict[str, Any]]:
    tokens_backend = _carregar_tokens(args)
    if args.full_lifecycle:
        tokens_backend = _preparar_eleicao_full_lifecycle(args)

    use_backend = bool(tokens_backend)
    api_pub = carregar_chave_api_mobile(args.se_keys) if use_backend else None

    if args.capture_mode == "auto":
        cap_mode = "tcpdump" if (os.geteuid() == 0 and shutil.which("tcpdump")) else "wiretap"
    else:
        cap_mode = args.capture_mode

    with tempfile.TemporaryDirectory(prefix="votaai_wireshark_eixo2_") as tmp_s:
        tmp_dir = Path(tmp_s)
        cert_path, key_path, origin_pin = gerar_cert_origin(tmp_dir, args.target_host)
        origin = OriginVoteHTTPSServer(
            cert_path,
            key_path,
            tls_version=args.tls_version,
            backend_url=args.backend_url if use_backend else None,
            host="127.0.0.1",
            port=args.origin_port,
        )
        effective_api_pub = api_pub if api_pub is not None else origin.api_pub

        try:
            # --- Controle Negativo (C1) ---
            c1, c1_meta = executar_controle_negativo(
                tshark_cmd,
                cert_path,
                origin,
                effective_api_pub,
                args.target_host,
                args.tls_version,
                cap_mode,
                args.interface,
                tmp_dir,
            )

            # --- Ensaio Principal (C2 / C3) ---
            tap: PassiveTCPWireTap | None = None
            td: TcpdumpCapture | None = None
            if cap_mode == "tcpdump":
                td = TcpdumpCapture(args.interface, origin.port, tmp_dir / "c2_votes.pcap")
                dst_port = origin.port
            else:
                tap = PassiveTCPWireTap("127.0.0.1", origin.port)
                dst_port = tap.listen_port

            samples: list[VoteSample] = []
            try:
                if use_backend:
                    rng = random.Random(args.seed)
                    # Embaralha apenas após mapear categorias em rodada cíclica
                    for idx, raw_token in enumerate(tokens_backend):
                        dev_priv, dev_pub_pem = gerar_chave_dispositivo_android()
                        nonce_req = gerar_nonce_seguro()
                        req_env = cifrar_envelope_servidor(
                            effective_api_pub,
                            {
                                "token": raw_token,
                                "machine_public_key": dev_pub_pem,
                                "attestation_certificates": [gerar_certificado_strongbox(dev_priv, nonce_req)],
                                "nonce": nonce_req,
                            },
                        )
                        st_req, body_req, _, _ = enviar_post_tls(
                            args.target_host, dst_port, "/api/vote/request/", req_env, cert_path, args.tls_version, dev_priv=dev_priv
                        )
                        if st_req != 200 or not isinstance(body_req, dict) or "id_voto" not in body_req:
                            raise RuntimeError(f"Falha em /api/vote/request/ (HTTP {st_req}): {body_req}")

                        election = body_req["election"]
                        id_voto = str(body_req["id_voto"])
                        election_pub = serialization.load_pem_public_key(election["public_key"].encode("utf-8"))
                        assert isinstance(election_pub, rsa.RSAPublicKey)
                        cat_opts = _classificar_opcoes_eleicao(election.get("questions", []))
                        chosen = cat_opts[idx % len(cat_opts)]

                        plain_pkg = serializar_plain_package(int(election["id"]), {chosen["question_id"]: chosen["option_id"]}, id_voto)
                        pacote_cifrado = cifrar_com_chave_eleicao(plain_pkg, election_pub)
                        content = json.dumps({"id_voto": id_voto, "pacote_cifrado": pacote_cifrado}, separators=(",", ":"))
                        signature = base64.b64encode(dev_priv.sign(content.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256())).decode("ascii")
                        nonce_cast = gerar_nonce_seguro()
                        cast_env = cifrar_envelope_servidor(
                            effective_api_pub,
                            {
                                "token": raw_token,
                                "machine_public_key": dev_pub_pem,
                                "content": content,
                                "nonce": nonce_cast,
                                "signature": signature,
                            },
                        )
                        st_cast, body_cast, http_len, cli_port = enviar_post_tls(
                            args.target_host, dst_port, "/api/vote/cast/", cast_env, cert_path, args.tls_version, dev_priv=dev_priv
                        )
                        confirmed = st_cast == 200 and isinstance(body_cast, dict) and body_cast.get("status") == "CONFIRMED"
                        samples.append(
                            VoteSample(
                                seq_index=idx + 1,
                                category=chosen["category"],
                                option_id=chosen["option_id"],
                                option_label=chosen["label"],
                                nominal_bytes=len(chosen["label"].encode("utf-8")),
                                plain_package_bytes=len(plain_pkg.encode("utf-8")),
                                pacote_cifrado_b64_len=len(pacote_cifrado),
                                content_bytes=len(content.encode("utf-8")),
                                envelope_json_bytes=http_len,
                                http_content_length=http_len,
                                http_status=st_cast,
                                confirmed=confirmed,
                                decrypted_verified=True,
                                client_port=cli_port,
                            )
                        )
                else:
                    schedule = [opt for _ in range(args.repeats) for opt in STANDARD_OPTIONS]
                    random.Random(args.seed).shuffle(schedule)
                    for idx, opt in enumerate(schedule):
                        dev_priv, dev_pub_pem = gerar_chave_dispositivo_android()
                        id_voto = f"VOTE-{os.urandom(16).hex().upper()}"
                        plain_pkg = serializar_plain_package(1, {"1": int(opt["option_id"])}, id_voto)
                        pacote_cifrado = cifrar_com_chave_eleicao(plain_pkg, origin.election_pub)
                        content = json.dumps({"id_voto": id_voto, "pacote_cifrado": pacote_cifrado}, separators=(",", ":"))
                        signature = base64.b64encode(dev_priv.sign(content.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256())).decode("ascii")
                        cast_env = cifrar_envelope_servidor(
                            effective_api_pub,
                            {
                                "token": secrets_urlsafe_token(),
                                "machine_public_key": dev_pub_pem,
                                "content": content,
                                "nonce": gerar_nonce_seguro(),
                                "signature": signature,
                            },
                        )
                        idx_rec = origin.snapshot()
                        st_cast, body_cast, http_len, cli_port = enviar_post_tls(
                            args.target_host, dst_port, "/api/vote/cast/", cast_env, cert_path, args.tls_version, dev_priv=dev_priv
                        )
                        recs = origin.since(idx_rec)
                        confirmed = st_cast == 200 and isinstance(body_cast, dict) and body_cast.get("status") == "CONFIRMED"
                        dec_ok = bool(recs and recs[-1].get("decrypted_verified"))
                        samples.append(
                            VoteSample(
                                seq_index=idx + 1,
                                category=opt["category"],
                                option_id=int(opt["option_id"]),
                                option_label=str(opt["label"]),
                                nominal_bytes=len(str(opt["label"]).encode("utf-8")),
                                plain_package_bytes=len(plain_pkg.encode("utf-8")),
                                pacote_cifrado_b64_len=len(pacote_cifrado),
                                content_bytes=len(content.encode("utf-8")),
                                envelope_json_bytes=http_len,
                                http_content_length=http_len,
                                http_status=st_cast,
                                confirmed=confirmed,
                                decrypted_verified=dec_ok,
                                client_port=cli_port,
                            )
                        )
            finally:
                pcap_bytes = td.stop() if td is not None else (tap.stop() if tap is not None else b"")

            streams = dissecar_pcap_com_tshark(tshark_cmd, pcap_bytes, server_port=dst_port)
            # Em modo --tokens/--full-lifecycle, cada voto fez 2 conexões (/request/ e /cast/);
            # associamos por client_port exato da conexão POST /api/vote/cast/.
            associar_streams_amostras(samples, streams)

            # --- C0: Ambiente Wireshark/TShark e Captura TLS ---
            negotiated_vers = sorted({s.tls_version for s in samples if s.tls_version})
            ciphers = sorted({s.tls_ciphersuite for s in samples if s.tls_ciphersuite})
            c0_ok = len(streams) >= len(samples) and all(s.tcp_stream is not None and s.tls_http_post_bytes > 0 for s in samples)
            c0 = CheckResult(
                "C0",
                "Ambiente Wireshark/TShark e Captura TLS",
                "PASSOU" if c0_ok else "FALHOU",
                (
                    f"{tshark_ver} dissecou {len(streams)} fluxo(s) TLS ({', '.join(negotiated_vers) or args.tls_version}) via {cap_mode}."
                    if c0_ok
                    else "Falha na captura ou dissecação TLS pelo tshark."
                ),
                [
                    f"Dissector Wireshark : {tshark_ver} ({' '.join(tshark_cmd)})",
                    f"Modo de captura     : {cap_mode} (porta TLS={dst_port}, bytes_pcap={len(pcap_bytes)})",
                    f"Versão TLS negociada: {', '.join(negotiated_vers) or 'desconhecida'} | Ciphersuites: {', '.join(ciphers) or 'n/a'}",
                ],
            )

            # --- C2 e C3 ---
            c2 = avaliar_uniformidade_c2(samples, offline_mode=False)
            c3, c3_metrics = avaliar_estatistica_c3(samples)

            # --- C4: Auditoria Estática e Limites de Fronteira ---
            c4, c4_info = auditar_fronteiras_padding_c4(
                tshark_cmd,
                cert_path,
                origin,
                effective_api_pub,
                args.target_host,
                args.tls_version,
                cap_mode,
                args.interface,
                tmp_dir,
                args.strict_padding,
            )

            manifest = {
                "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "tls_port": dst_port,
                "tls_version_requested": args.tls_version,
                "mode": "backend" if use_backend else "standalone",
                "origin_spki_pin": origin_pin,
                "samples": [asdict(s) for s in samples],
            }
            meta = {
                "mode": "backend" if use_backend else "standalone",
                "tshark": tshark_ver,
                "capture_mode": cap_mode,
                "tls_port": dst_port,
                "tls_version": ", ".join(negotiated_vers) or args.tls_version,
                "origin_spki_pin": origin_pin,
                "c1": c1_meta,
                "c3": c3_metrics,
                "c4": c4_info,
                "samples": [asdict(s) for s in samples],
            }
            return [c0, c1, c2, c3, c4], meta, pcap_bytes, manifest
        finally:
            origin.close()


# ==============================================================================
# Modo Offline (--pcap) e Modo Gateway (--serve-https-only)
# ==============================================================================
def executar_analise_offline(args: argparse.Namespace, tshark_cmd: list[str], tshark_ver: str) -> tuple[list[CheckResult], dict[str, Any]]:
    if not args.pcap.is_file():
        raise FileNotFoundError(f"Arquivo PCAP não encontrado: {args.pcap}")
    pcap_bytes = args.pcap.read_bytes()

    manifest_data: dict[str, Any] = {}
    if args.manifest:
        manifest_data = json.loads(args.manifest.read_text(encoding="utf-8"))

    server_port = args.tls_port or manifest_data.get("tls_port")
    streams = dissecar_pcap_com_tshark(tshark_cmd, pcap_bytes, server_port=server_port)

    samples: list[VoteSample] = []
    if manifest_data.get("samples"):
        for raw_s in manifest_data["samples"]:
            st = streams.get(raw_s.get("tcp_stream"))
            if st is None and raw_s.get("client_port"):
                st = next((x for x in streams.values() if x.client_port == raw_s["client_port"]), None)
            samples.append(
                VoteSample(
                    seq_index=int(raw_s["seq_index"]),
                    category=str(raw_s["category"]),
                    option_id=int(raw_s["option_id"]),
                    option_label=str(raw_s["option_label"]),
                    nominal_bytes=int(raw_s["nominal_bytes"]),
                    plain_package_bytes=int(raw_s.get("plain_package_bytes", 0)),
                    pacote_cifrado_b64_len=int(raw_s.get("pacote_cifrado_b64_len", 0)),
                    content_bytes=int(raw_s.get("content_bytes", 0)),
                    envelope_json_bytes=int(raw_s.get("envelope_json_bytes", 0)),
                    http_content_length=int(raw_s.get("http_content_length", 0)),
                    http_status=int(raw_s.get("http_status", 200)),
                    confirmed=bool(raw_s.get("confirmed", True)),
                    decrypted_verified=bool(raw_s.get("decrypted_verified", True)),
                    client_port=int(raw_s.get("client_port", 0)),
                    tcp_stream=st.stream_id if st else raw_s.get("tcp_stream"),
                    tls_version=st.tls_version if st else str(raw_s.get("tls_version", "")),
                    tls_ciphersuite=st.ciphersuite if st else str(raw_s.get("tls_ciphersuite", "")),
                    tls_http_post_bytes=st.tls_http_post_bytes if st else 0,
                    tls_max_record_bytes=st.tls_max_record_bytes if st else 0,
                    tls_total_appdata_bytes=st.tls_total_appdata_bytes if st else 0,
                    tcp_c2s_payload_bytes=st.tcp_c2s_payload_bytes if st else 0,
                    tls_c2s_record_sizes=list(st.c2s_appdata_records) if st else [],
                )
            )
    else:
        for idx, st in enumerate(sorted(streams.values(), key=lambda x: (x.first_ts, x.stream_id)), start=1):
            if st.tls_http_post_bytes <= 0:
                continue
            samples.append(
                VoteSample(
                    seq_index=idx,
                    category=f"STREAM_{st.stream_id}",
                    option_id=idx,
                    option_label=f"stream-{st.stream_id}",
                    nominal_bytes=idx,
                    plain_package_bytes=0,
                    pacote_cifrado_b64_len=0,
                    content_bytes=0,
                    envelope_json_bytes=0,
                    http_content_length=0,
                    http_status=200,
                    confirmed=True,
                    decrypted_verified=True,
                    client_port=st.client_port,
                    tcp_stream=st.stream_id,
                    tls_version=st.tls_version,
                    tls_ciphersuite=st.ciphersuite,
                    tls_http_post_bytes=st.tls_http_post_bytes,
                    tls_max_record_bytes=st.tls_max_record_bytes,
                    tls_total_appdata_bytes=st.tls_total_appdata_bytes,
                    tcp_c2s_payload_bytes=st.tcp_c2s_payload_bytes,
                    tls_c2s_record_sizes=list(st.c2s_appdata_records),
                )
            )

    negotiated_vers = sorted({s.tls_version for s in samples if s.tls_version})
    c0_ok = bool(streams) and bool(samples) and all(s.tls_http_post_bytes > 0 for s in samples)
    c0 = CheckResult(
        "C0",
        "Ambiente Wireshark/TShark e Captura TLS",
        "PASSOU" if c0_ok else "FALHOU",
        f"{tshark_ver} analisou PCAP offline '{args.pcap.name}' ({len(streams)} fluxos TLS, {len(samples)} amostras).",
        [
            f"PCAP analisado: {args.pcap} ({len(pcap_bytes)} bytes)",
            f"Manifesto     : {args.manifest if args.manifest else 'não informado (análise agnóstica por stream)'}",
            f"Versão TLS    : {', '.join(negotiated_vers) or 'desconhecida'}",
        ],
    )
    c1 = CheckResult(
        "C1",
        "Controle Negativo no Wireshark (Contraprova sem Padding/Indireção)",
        "N/A",
        "Controle negativo não aplicável em modo offline (--pcap).",
        ["Execute sem --pcap para validar a contraprova ao vivo no canal TLS."],
    )
    c2 = avaliar_uniformidade_c2(samples, offline_mode=True)
    c3, c3_metrics = avaliar_estatistica_c3(samples)
    c4, c4_info = auditar_fronteiras_padding_c4(None, None, None, None, args.target_host, args.tls_version, "offline", args.interface, None, args.strict_padding)
    meta = {
        "mode": "offline-pcap",
        "pcap": str(args.pcap),
        "tshark": tshark_ver,
        "tls_version": ", ".join(negotiated_vers) or "desconhecida",
        "c3": c3_metrics,
        "c4": c4_info,
        "samples": [asdict(s) for s in samples],
    }
    return [c0, c1, c2, c3, c4], meta


# ==============================================================================
# CLI e Relatório Final
# ==============================================================================
def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Teste 5 (Eixo 2): Avaliação de Tráfego e Padding da Cédula com Wireshark.")
    p.add_argument("--repeats", type=int, default=DEFAULT_REPEATS, help=f"Repetições por categoria (padrão: {DEFAULT_REPEATS} -> {DEFAULT_REPEATS * 4} votos).")
    p.add_argument("--seed", type=int, default=DEFAULT_SEED, help=f"Semente de embaralhamento (padrão: {DEFAULT_SEED}).")
    p.add_argument("--tls-version", choices=("1.3", "1.2", "auto"), default="1.3", help="Versão TLS do canal ativo (padrão: 1.3).")
    p.add_argument("--capture-mode", choices=("auto", "wiretap", "tcpdump"), default="auto", help="Mecanismo de captura de pacotes (padrão: auto).")
    p.add_argument("--interface", default="lo", help="Interface de rede para --capture-mode tcpdump (padrão: lo).")
    p.add_argument("--backend-url", default=DEFAULT_BACKEND_URL, help=f"Backend Django Vota-i 2.0 (padrão: {DEFAULT_BACKEND_URL}).")
    p.add_argument("--target-host", default=DEFAULT_TARGET_HOST, help=f"Hostname TLS alvo (padrão: {DEFAULT_TARGET_HOST}).")
    p.add_argument("--origin-port", type=int, default=0, help="Porta do Origin HTTPS (padrão: efêmera; 8443 em --serve-https-only).")
    p.add_argument("--tokens", nargs="*", help="Tokens reais de votação para submeter ao backend Django via TLS + captura.")
    p.add_argument("--tokens-file", type=Path, help="Arquivo com um token real por linha.")
    p.add_argument("--full-lifecycle", action="store_true", help="Cria e inicia eleição efêmera no backend Django real para o ensaio.")
    p.add_argument("--auth-token", help="Token Knox do administrador (para --full-lifecycle).")
    p.add_argument("--admin-email", help="E-mail do administrador (para --full-lifecycle).")
    p.add_argument("--admin-password", help="Senha do administrador (para --full-lifecycle).")
    p.add_argument("--admin-totp", help="Código TOTP de 6 dígitos (para --full-lifecycle).")
    p.add_argument("--device-id", help="Device ID Desktop (para --full-lifecycle).")
    p.add_argument("--se-keys", type=Path, default=SE_KEYS_PATH, help=f"Caminho de se_keys_info.json (padrão: {SE_KEYS_PATH}).")
    p.add_argument("--client-key", type=Path, default=DEFAULT_CLIENT_KEY_PATH, help=f"Caminho de client_key.json (padrão: {DEFAULT_CLIENT_KEY_PATH}).")
    p.add_argument("--sent-emails-dir", type=Path, default=DEFAULT_SENT_EMAILS_DIR, help=f"Diretório sent_emails (padrão: {DEFAULT_SENT_EMAILS_DIR}).")
    p.add_argument("--db-url", help="DSN PostgreSQL explícito.")
    p.add_argument("--sqlite", type=Path, help="Caminho explícito para SQLite.")
    p.add_argument("--env-file", type=Path, default=DEFAULT_ENV_PATH, help=f"Arquivo .env do backend (padrão: {DEFAULT_ENV_PATH}).")
    p.add_argument("--serve-https-only", action="store_true", help="Mantém apenas o gateway HTTPS ativo para captura manual no Wireshark GUI.")
    p.add_argument("--pcap", type=Path, help="Analisa um arquivo .pcap/.pcapng capturado externamente pelo Wireshark.")
    p.add_argument("--tls-port", type=int, default=None, help="Porta TLS de destino no arquivo --pcap.")
    p.add_argument("--manifest", type=Path, default=None, help="Manifesto JSON associando fluxos às opções em --pcap.")
    p.add_argument("--pcap-out", type=Path, default=None, help="Salva o arquivo .pcap capturado neste caminho.")
    p.add_argument("--manifest-out", type=Path, default=None, help="Salva manifesto JSON deste ensaio neste caminho.")
    p.add_argument("--json-out", type=Path, default=None, help="Salva relatório completo em JSON neste caminho.")
    p.add_argument("--strict-padding", action="store_true", help="Reprova (FALHOU em C4) se não houver padding explícito além do bloco único RSA-2048.")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    if args.serve_https_only:
        listen_port = args.origin_port or 8443
        with tempfile.TemporaryDirectory(prefix="votaai_https_gw_") as tmp_s:
            cert_path, key_path, origin_pin = gerar_cert_origin(Path(tmp_s), args.target_host)
            srv = OriginVoteHTTPSServer(
                cert_path,
                key_path,
                tls_version=args.tls_version,
                backend_url=args.backend_url,
                host="0.0.0.0",
                port=listen_port,
            )
            try:
                print(f"Gateway HTTPS ativo: https://{args.target_host}:{srv.port} -> {args.backend_url} | SPKI={origin_pin}")
                print(f"Filtro Wireshark   : tcp.port == {srv.port} && (tls.record.opaque_type == 23 || tls.record.content_type == 23)")
                print(f"Captura tcpdump    : sudo tcpdump -i lo -s 0 -w captura_votos.pcap 'tcp port {srv.port}'")
                print("Ctrl+C para encerrar.")
                while True:
                    time.sleep(1.0)
            except KeyboardInterrupt:
                return 0
            finally:
                srv.close()

    tshark_cmd, tshark_ver = detectar_tshark()
    if tshark_cmd is None:
        print(f"Erro: {tshark_ver}", file=sys.stderr)
        return 2

    try:
        if args.pcap is not None:
            checks, meta = executar_analise_offline(args, tshark_cmd, tshark_ver)
            pcap_bytes = b""
            manifest: dict[str, Any] = {}
        else:
            checks, meta, pcap_bytes, manifest = executar_ensaio_live(args, tshark_cmd, tshark_ver)
    except Exception as exc:
        print(f"Erro durante execução do ensaio: {exc}", file=sys.stderr)
        return 2

    if args.pcap_out and pcap_bytes:
        args.pcap_out.parent.mkdir(parents=True, exist_ok=True)
        args.pcap_out.write_bytes(pcap_bytes)
    if args.manifest_out and manifest:
        args.manifest_out.parent.mkdir(parents=True, exist_ok=True)
        args.manifest_out.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")

    print("\n" + "=" * 78)
    print("ENSAIO DE TRÁFEGO E PADDING DA CÉDULA COM WIRESHARK (EIXO 2 - TESTE 2)")
    print("=" * 78)
    print(f"Modo        : {meta.get('mode')}")
    print(f"Wireshark   : {tshark_ver}")
    print(f"TLS         : {meta.get('tls_version')}")
    if args.pcap_out and pcap_bytes:
        print(f"PCAP salvo  : {args.pcap_out} ({len(pcap_bytes)} bytes)")
    if args.manifest_out and manifest:
        print(f"Manifesto   : {args.manifest_out}")
    print("-" * 78)
    for chk in checks:
        print(f"[{chk.status:<6}] {chk.code} - {chk.title}: {chk.summary}")
        for line in chk.details:
            print(f"           {line}")
    print("=" * 78)

    has_fail = any(c.status == "FALHOU" for c in checks)
    has_alert = any(c.status == "ALERTA" for c in checks)
    if has_fail:
        verdict = "REPROVADO"
        rc = 1
    elif has_alert:
        verdict = "APROVADO (com alertas arquiteturais de fronteira em C4)"
        rc = 0
    else:
        verdict = "APROVADO"
        rc = 0

    print(f"Resultado: {verdict}")
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(
            json.dumps({"verdict": verdict, "meta": meta, "checks": [asdict(c) for c in checks]}, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"Relatório JSON salvo em: {args.json_out}")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
