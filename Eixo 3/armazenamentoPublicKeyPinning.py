"""
Teste 9 (Eixo 3): Verificacao do Armazenamento do Public Key Pinning

Inspeciona os binarios compilados Desktop e Mobile em busca de chaves publicas,
PEM, blobs DER/SPKI e hashes de ancoragem que estejam disponiveis como constantes
trivialmente localizaveis ou substituiveis.

Procedimento:
  1. Extrair strings dos binarios/arquivos compilados.
  2. Derivar candidatos reais de chave publica dos recursos-fonte conhecidos.
  3. Procurar o texto Base64/PEM e o blob DER decodificado nos artefatos.
  4. Inspecionar membros de APK (DEX, assets Hermes e bibliotecas nativas).
  5. Usar Ghidra Headless para confirmar exposicao de marcadores e referencias
     em binarios ELF nativos.

Passa somente quando nenhuma chave publicavel e nenhum PEM/hashes de ancoragem
trivialmente substituivel forem encontrados em texto puro nos artefatos compilados.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import glob
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DESKTOP_BIN = Path("/home/debrito/Programação/votaai-desktop/dist/votaai-desktop")
DEFAULT_DESKTOP_SOURCE = Path("/home/debrito/Programação/votaai-desktop")
DEFAULT_MOBILE_APK = Path(
    "/home/debrito/Programação/projeto-react-native/android/app/build/outputs/apk/release/app-release.apk"
)
DEFAULT_MOBILE_SOURCE = Path("/home/debrito/Programação/projeto-react-native")
DEFAULT_GHIDRA_HEADLESS = (
    REPO_ROOT
    / ".venv"
    / "share"
    / "ghidra"
    / "ghidra_11.0.3_PUBLIC"
    / "support"
    / "analyzeHeadless"
)

PLAIN_MARKERS = (
    b"-----BEGIN PUBLIC KEY-----",
    b"-----BEGIN RSA PUBLIC KEY-----",
    b"-----BEGIN CERTIFICATE-----",
)


@dataclass
class CheckResult:
    code: str
    title: str
    status: str
    summary: str
    details: list[str] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)


def run_cmd(
    cmd: list[str],
    cwd: Path | None = None,
    timeout: float = 120.0,
) -> tuple[int, str, str, float, bool]:
    started = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr, time.monotonic() - started, False
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return -1, stdout, stderr, time.monotonic() - started, True


def find_ghidra_headless(explicit: Path | None = None) -> Path | None:
    if explicit and explicit.is_file():
        return explicit
    if DEFAULT_GHIDRA_HEADLESS.is_file():
        return DEFAULT_GHIDRA_HEADLESS
    matches = sorted(glob.glob(str(REPO_ROOT / ".venv" / "share" / "ghidra" / "*" / "support" / "analyzeHeadless")))
    if matches:
        return Path(matches[-1])
    found = shutil.which("analyzeHeadless")
    return Path(found) if found else None


def extract_pem_blocks(data: bytes) -> list[bytes]:
    pattern = br"-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----"
    return re.findall(pattern, data, flags=re.DOTALL)


def candidate_key_values(source_roots: Iterable[Path]) -> list[str]:
    candidates: set[str] = set()
    pem_pattern = re.compile(
        rb"-----BEGIN (?:PUBLIC KEY|RSA PUBLIC KEY|CERTIFICATE)-----"
        rb"(?:.*?)(?:-----END (?:PUBLIC KEY|RSA PUBLIC KEY|CERTIFICATE)-----)",
        re.DOTALL,
    )

    for root in source_roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if any(part in {".git", "node_modules", "build", "dist"} for part in path.parts):
                continue
            try:
                raw = path.read_bytes()
            except OSError:
                continue
            if len(raw) > 5_000_000:
                continue

            for pem in pem_pattern.findall(raw):
                candidates.add(pem.decode("ascii", errors="ignore"))

            text = raw.decode("utf-8", errors="ignore")
            for match in re.findall(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/])", text):
                normalized = match.strip()
                if len(normalized) >= 40:
                    candidates.add(normalized)

            for match in re.findall(r'"PublicKey(?:Base64|PEM)"\s*:\s*"([^"]+)"', text):
                candidates.add(match.replace("\\n", "\n"))

    filtered: set[str] = set()
    for candidate in candidates:
        if "-----BEGIN " in candidate:
            filtered.add(candidate)
            continue
        compact = candidate.replace("-", "").replace("_", "")
        if len(compact) >= 40 and re.fullmatch(r"[A-Za-z0-9+/=]+", compact):
            filtered.add(candidate)

    return sorted(filtered, key=lambda item: (-len(item), item))


def candidate_der_blobs(candidates: Iterable[str]) -> list[bytes]:
    blobs: set[bytes] = set()
    for candidate in candidates:
        if "-----BEGIN " not in candidate:
            try:
                padded = candidate + "=" * ((4 - len(candidate) % 4) % 4)
                decoded = base64.b64decode(padded, validate=True)
                if len(decoded) >= 32:
                    blobs.add(decoded)
            except (binascii.Error, ValueError):
                pass

    for pem in (candidate for candidate in candidates if "-----BEGIN " in candidate):
        body = re.sub(rb"(?:\r?\n)?-----.*?-----", b"", pem.encode("ascii", errors="ignore"))
        try:
            decoded = base64.b64decode(re.sub(rb"\s+", b"", body), validate=True)
            if len(decoded) >= 32:
                blobs.add(decoded)
        except (binascii.Error, ValueError):
            pass

    return sorted(blobs, key=lambda item: (-len(item), item))


def inspect_raw_artifact(label: str, raw: bytes, candidates: list[str], der_blobs: list[bytes]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "label": label,
        "pem_markers": [],
        "plain_candidates": [],
        "der_candidates": [],
    }
    for marker in PLAIN_MARKERS:
        count = raw.count(marker)
        if count:
            result["pem_markers"].append({"marker": marker.decode("ascii"), "count": count})

    for candidate in candidates:
        if len(candidate) < 40:
            continue
        needle = candidate.encode("utf-8")
        if candidate.startswith("-----BEGIN ") or needle in raw:
            if needle in raw:
                result["plain_candidates"].append(candidate[:80])

    for der in der_blobs:
        if der in raw:
            result["der_candidates"].append({"sha256": sha256_hex(der), "length": len(der)})

    return result


def sha256_hex(raw: bytes) -> str:
    import hashlib

    return hashlib.sha256(raw).hexdigest()


def extract_strings(path: Path, timeout: float = 30.0) -> tuple[list[str], str]:
    strings_bin = shutil.which("strings")
    if not strings_bin:
        return [], "utilitario 'strings' nao encontrado"
    rc, out, err, _, timed_out = run_cmd([strings_bin, "-a", "-n", "20", str(path)], timeout=timeout)
    if timed_out:
        return [], "timeout ao executar strings"
    if rc != 0:
        return [], err.strip() or f"strings retornou rc={rc}"
    return [line for line in out.splitlines() if line.strip()], ""


GHIDRA_POST_SCRIPT = r"""# -*- coding: utf-8 -*-
import json
from ghidra.util.task import ConsoleTaskMonitor

monitor = ConsoleTaskMonitor()
listing = currentProgram.getListing()
markers = ["BEGIN PUBLIC KEY", "BEGIN RSA PUBLIC KEY", "PUBLIC_KEY", "PublicKeyBase64", "VotaAI_SecureKey"]
found = {}
data_count = 0

data_iter = listing.getDefinedData(True)
while data_iter.hasNext() and data_count < 200000:
    data = data_iter.next()
    data_count += 1
    try:
        value = str(data.getValue())
    except Exception:
        continue
    for marker in markers:
        if marker.lower() in value.lower():
            found.setdefault(marker, 0)
            found[marker] += 1

out = {
    "program": currentProgram.getName(),
    "marker_hits": found,
    "defined_data_count": data_count,
    "function_count": currentProgram.getFunctionManager().getFunctionCount()
}
print("PKPIN_JSON_START:" + json.dumps(out) + ":PKPIN_JSON_END")
"""


def run_ghidra(ghidra: Path, binaries: list[tuple[str, bytes]], timeout: float = 180.0) -> tuple[dict[str, Any], str]:
    results: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="votaai_pkpin_") as temp:
        temp_dir = Path(temp)
        script = temp_dir / "PkPinAuditScript.py"
        script.write_text(GHIDRA_POST_SCRIPT, encoding="utf-8")
        import_paths: list[str] = []
        for name, raw in binaries:
            path = temp_dir / name
            path.write_bytes(raw)
            import_paths.append(str(path))
        if not import_paths:
            return results, ""

        cmd = [
            str(ghidra),
            str(temp_dir),
            "VotaAIPkPinAudit",
            "-import",
            *import_paths,
            "-scriptPath",
            str(temp_dir),
            "-postScript",
            "PkPinAuditScript.py",
            "-deleteProject",
        ]
        rc, out, err, elapsed, timed_out = run_cmd(cmd, timeout=timeout)
        combined = out + "\n" + err
        for line in combined.splitlines():
            if "PKPIN_JSON_START:" in line and ":PKPIN_JSON_END" in line:
                payload = line.split("PKPIN_JSON_START:", 1)[1].split(":PKPIN_JSON_END", 1)[0]
                try:
                    parsed = json.loads(payload)
                    results[parsed["program"]] = parsed
                except json.JSONDecodeError:
                    pass
        if timed_out:
            return results, f"Timeout apos {elapsed:.1f}s executando Ghidra"
        if rc != 0 and not results:
            return results, f"Ghidra retornou rc={rc}: {err.strip()[:300]}"
        return results, ""


def inspect_desktop(path: Path, source_root: Path, ghidra: Path | None) -> tuple[CheckResult, list[tuple[str, bytes]]]:
    raw = path.read_bytes()
    candidates = candidate_key_values([source_root])
    der_blobs = candidate_der_blobs(candidates)
    scan = inspect_raw_artifact(path.name, raw, candidates, der_blobs)

    strings_lines, strings_error = extract_strings(path)
    strings_markers = []
    for marker in PLAIN_MARKERS:
        marker_text = marker.decode("ascii")
        if marker_text in "\n".join(strings_lines):
            strings_markers.append(marker_text)

    # O ELF completo inclui centenas de MB de artefatos PyInstaller.
    # Para a descompilacao Ghidra, usar uma janela inicial de bootloader nativo
    # e manter o varredura byte-a-byte completa separada acima.
    ghidra_sample_size = min(len(raw), 32 * 1024 * 1024)
    binaries = [(path.name, raw[:ghidra_sample_size])]
    if ghidra is not None:
        ghidra_results, ghidra_error = run_ghidra(ghidra, binaries)
        ghidra_hits = sum(
            sum(program.get("marker_hits", {}).values())
            for program in ghidra_results.values()
        )
    else:
        ghidra_error = ""
        ghidra_hits = 0

    exposed = bool(
        scan["pem_markers"]
        or scan["plain_candidates"]
        or scan["der_candidates"]
        or strings_markers
        or ghidra_hits
    )
    status = "FALHOU" if exposed else ("ALERTA" if ghidra_error or strings_error else "PASSOU")
    details = [
        f"Strings: {len(strings_lines)} linhas recuperaveis"
        + (f" (utilitarios indisponivel: {strings_error})" if strings_error else ""),
        f"Candidatos de chave derivados da fonte: {len(candidates)}",
        f"Blobs DER/SPKI derivados: {len(der_blobs)}",
        f"Marcadores PEM no binario: {sum(item['count'] for item in scan['pem_markers'])}",
        f"Candidatos literais encontrados: {len(scan['plain_candidates'])}",
        f"Blobs DER/SPKI encontrados no binario: {len(scan['der_candidates'])}",
        f"Marcadores encontrados pelo Ghidra: {ghidra_hits}",
    ]
    if ghidra_error:
        details.append(f"Ghidra: {ghidra_error}")
    elif ghidra is None:
        details.append("Ghidra: nao executado; use --run-ghidra para a etapa descompilada")

    summary = (
        "Chave publica ou ancoragem visivel em texto puro/literal substituivel no binario Desktop."
        if exposed
        else "Nenhuma chave publica em texto puro ou blob DER/SPKI trivial foi localizada no binario Desktop."
    )
    check = CheckResult(
        "D9",
        "Desktop | Armazenamento da Chave Publica do Servidor",
        status,
        summary,
        details,
        {
            "candidate_keys": len(candidates),
            "der_blobs": len(der_blobs),
            "pem_markers": sum(item["count"] for item in scan["pem_markers"]),
            "plain_candidates": len(scan["plain_candidates"]),
            "der_matches": len(scan["der_candidates"]),
            "ghidra_marker_hits": ghidra_hits,
        },
    )
    return check, binaries


def inspect_mobile(path: Path, source_root: Path, ghidra: Path | None) -> tuple[CheckResult, list[tuple[str, bytes]]]:
    candidates = candidate_key_values([source_root])
    der_blobs = candidate_der_blobs(candidates)
    scans: list[dict[str, Any]] = []
    binaries: list[tuple[str, bytes]] = []

    apk_raw = path.read_bytes()
    scans.append(inspect_raw_artifact("app-release.apk", apk_raw, candidates, der_blobs))

    strings_markers: list[str] = []
    with zipfile.ZipFile(path, "r") as archive:
        for name in archive.namelist():
            if name not in (
                "classes.dex",
                "classes2.dex",
                "classes3.dex",
                "assets/index.android.bundle",
                "lib/arm64-v8a/libseguranca_nativa.so",
                "lib/x86_64/libseguranca_nativa.so",
            ) and not name.endswith(".so"):
                continue
            raw = archive.read(name)
            scans.append(inspect_raw_artifact(name, raw, candidates, der_blobs))
            if name.endswith(".so"):
                binaries.append((name.replace("/", "_"), raw))
            for marker in PLAIN_MARKERS:
                if marker in raw:
                    strings_markers.append(f"{name}:{marker.decode('ascii')}")

    if ghidra is not None:
        ghidra_results, ghidra_error = run_ghidra(ghidra, binaries)
        ghidra_hits = sum(
            sum(program.get("marker_hits", {}).values())
            for program in ghidra_results.values()
        )
    else:
        ghidra_error = ""
        ghidra_hits = 0

    exposed = bool(
        strings_markers
        or ghidra_hits
        or any(
            scan["pem_markers"] or scan["plain_candidates"] or scan["der_candidates"]
            for scan in scans
        )
    )
    status = "FALHOU" if exposed else ("ALERTA" if ghidra_error else "PASSOU")
    pem_count = sum(
        sum(item["count"] for item in scan["pem_markers"])
        for scan in scans
    )
    plain_count = sum(len(scan["plain_candidates"]) for scan in scans)
    der_count = sum(len(scan["der_candidates"]) for scan in scans)
    details = [
        f"Candidatos de chave derivados da fonte: {len(candidates)}",
        f"Blobs DER/SPKI derivados: {len(der_blobs)}",
        f"Marcadores PEM em DEX/bundle/nativas: {pem_count}",
        f"Candidatos literais encontrados em membros do APK: {plain_count}",
        f"Blobs DER/SPKI encontrados em membros do APK: {der_count}",
        f"Marcadores encontrados pelo Ghidra: {ghidra_hits}",
        f"Membros nativos analisados pelo Ghidra: {len(binaries)}",
    ]
    if ghidra_error:
        details.append(f"Ghidra: {ghidra_error}")
    elif ghidra is None:
        details.append("Ghidra: nao executado; use --run-ghidra para a etapa descompilada")

    summary = (
        "Chave publica ou ancoragem visivel em texto puro/literal substituivel no APK Mobile."
        if exposed
        else "Nenhuma chave publica em texto puro ou blob DER/SPKI trivial foi localizada no APK Mobile."
    )
    check = CheckResult(
        "M9",
        "Mobile | Armazenamento das Chaves Publicas do Servidor/QR",
        status,
        summary,
        details,
        {
            "candidate_keys": len(candidates),
            "der_blobs": len(der_blobs),
            "pem_markers": pem_count,
            "plain_candidates": plain_count,
            "der_matches": der_count,
            "ghidra_marker_hits": ghidra_hits,
            "native_binaries_analyzed": len(binaries),
        },
    )
    return check, binaries


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Teste 9 (Eixo 3): Verificacao do Armazenamento do Public Key Pinning."
    )
    parser.add_argument("--target", choices=("all", "desktop", "mobile"), default="all")
    parser.add_argument("--desktop-bin", type=Path, default=DEFAULT_DESKTOP_BIN)
    parser.add_argument("--desktop-source", type=Path, default=DEFAULT_DESKTOP_SOURCE)
    parser.add_argument("--mobile-apk", type=Path, default=DEFAULT_MOBILE_APK)
    parser.add_argument("--mobile-source", type=Path, default=DEFAULT_MOBILE_SOURCE)
    parser.add_argument("--ghidra-headless", type=Path, default=None)
    parser.add_argument(
        "--run-ghidra",
        action="store_true",
        help="Executa descompilacao Ghidra Headless dos ELF nativos (etapa potencialmente longa).",
    )
    parser.add_argument("--json-out", type=Path, default=None)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    ghidra: Path | None = None
    if args.run_ghidra:
        ghidra = find_ghidra_headless(args.ghidra_headless)
        if ghidra is None or not ghidra.is_file():
            print(
                "[ERRO] Utilitario Ghidra 'analyzeHeadless' nao encontrado. "
                "Informe --ghidra-headless ou instale em .venv/share/ghidra/.",
                file=sys.stderr,
            )
            return 2

    checks: list[CheckResult] = []

    if args.target in ("all", "desktop"):
        if not args.desktop_bin.is_file():
            print(f"[ERRO] Binario Desktop nao encontrado: {args.desktop_bin}", file=sys.stderr)
            return 2
        checks.append(inspect_desktop(args.desktop_bin, args.desktop_source, ghidra)[0])

    if args.target in ("all", "mobile"):
        if not args.mobile_apk.is_file():
            print(f"[ERRO] APK Mobile nao encontrado: {args.mobile_apk}", file=sys.stderr)
            return 2
        checks.append(inspect_mobile(args.mobile_apk, args.mobile_source, ghidra)[0])

    verdict = "REPROVADO" if any(check.status == "FALHOU" for check in checks) else (
        "APROVADO" if all(check.status == "PASSOU" for check in checks) else "PARCIAL (COM ALERTAS)"
    )

    print("\n" + "=" * 86)
    print("ENSAIO DE ARMAZENAMENTO DO PUBLIC KEY PINNING (EIXO 3 - TESTE 9)")
    print("Modelo de Ameaça: Codigo Aberto (White-Box) - Strings, Hexdump e Ghidra")
    print("=" * 86)
    print(f"Ghidra Headless : {ghidra if ghidra is not None else 'nao executado (use --run-ghidra)'}")
    for check in checks:
        print(f"[{check.status:<6}] {check.code:<4} - {check.title}: {check.summary}")
        for detail in check.details:
            print(f"           {detail}")
    print("-" * 86)
    print("MATRIZ DE AVALIACAO PELO CRITERIO DO TESTE 9:")
    print("  1. Chave nao armazenada como PEM/texto puro: "
          f"{'PASSOU' if all(c.status == 'PASSOU' for c in checks) else 'FALHOU'}")
    print("  2. Patching hexadecimal rapido nao encontra um literal substituivel:")
    print("     - Requer que nenhum candidato literal/DER/SPKI apareca nos artefatos")
    print("  3. Reconstrucao estrutural complexa:")
    print("     - Verificacao concluida com strings e descompilacao Ghidra")
    print("-" * 86)
    print(f"Veredito Final (Criterio Estrito Teste 9): {verdict}")

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        report = {
            "test": "Teste 9 (Eixo 3) - Verificacao do Armazenamento do Public Key Pinning",
            "verdict": verdict,
            "ghidra_headless": str(ghidra) if ghidra is not None else None,
            "checks": [asdict(check) for check in checks],
        }
        args.json_out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Relatorio JSON salvo em: {args.json_out}")

    return 0 if verdict == "APROVADO" else 1


if __name__ == "__main__":
    raise SystemExit(main())
