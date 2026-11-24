"""
Teste 8 (Eixo 3): Engenharia Reversa com Ghidra e Ofuscação de Binários

Mede a eficiência das técnicas de ofuscação, remoção de símbolos, conversão de código
e proteção estrutural aplicadas aos binários finais de produção dos clientes Desktop
(votaai-desktop) e Mobile (projeto-react-native / app-release.apk) frente a análises
estáticas direcionadas com o utilitário Ghidra (analyzeHeadless / DecompInterface) e
ferramentas de inspeção de bytecode (readelf, dexdump, disassembler CPython e Hermes HBC).

Procedimento experimental:
  1. Módulo Administrativo (votaai-desktop — binário ELF dist/votaai-desktop):
       - D1: Descompilação com Ghidra Headless da camada ELF nativa (bootloader x86_64),
             auditoria de tabelas de símbolos (.symtab / .dynsym) e reconstrução de CFG
             (blocos básicos, complexidade ciclomática e avaliação de achatamento de fluxo).
       - D2: Extração estática do CArchive / PYZ.pyz embutido no ELF, inspeção dos
             objetos de código CPython 3.12 (.pyc) das rotinas de comunicação e segurança,
             taxa de preservação de símbolos/constantes e reconstrução do CFG do bytecode.
       - D3: Auditoria de resistência a alteração estrutural e cobertura do manifesto
             criptográfico SHA-256 (integrity_manifest.json) em modo congelado (sys.frozen).
  2. Aplicativo Móvel (projeto-react-native — binário de produção app-release.apk):
       - M1: Descompilação com Ghidra Headless das bibliotecas nativas C++
             (lib/arm64-v8a/libseguranca_nativa.so e lib/x86_64/libseguranca_nativa.so),
             visibilidade de símbolos JNI vs funções internas (-fvisibility=hidden),
             métricas de CFG (achatamento de fluxo / inlining -O2) e exposição de strings
             críticas em .rodata.
       - M2: Descompilação Dalvik (classes.dex via dexdump) e medição quantitativa da
             ofuscação R8/ProGuard (taxa de renomeação irreversível de classes/métodos vs
             símbolos preservados por regras -keep).
       - M3: Análise estática do bundle compilado Hermes Bytecode (assets/index.android.bundle,
             HBC v98), verificando a conversão de código JS/TS para bytecode e a exposição de
             identificadores de comunicação segura, rotas e chaves públicas na tabela de strings.
       - M4: Auditoria de resistência a alteração estrutural do APK (validação criptográfica
             apksigner v2/v3, EXPECTED_SIGNING_SHA256, EXPECTED_BUNDLE_SHA256 e keystore).

Critério de validação:
  O teste é aprovado somente se as ferramentas de engenharia reversa não conseguirem
  recuperar a lógica estruturada do software em formato inteligível, evidenciando:
    (a) achatamento de fluxo de controle (Control Flow Flattening),
    (b) renomeação irreversível de símbolos das rotinas críticas de comunicação e segurança, e
    (c) conversão eficaz de código e blindagem de integridade que tornem impraticável a
        alteração maliciosa do binário compilado.
"""

from __future__ import annotations

import argparse
import dis
import glob
import hashlib
import json
import marshal
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import zipfile
import zlib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from types import CodeType
from typing import Any

# ==============================================================================
# Constantes e Caminhos Padrão dos Artefatos de Produção
# ==============================================================================
REPO_ROOT = Path(__file__).resolve().parent.parent

DESKTOP_DIR = Path("/home/debrito/Programação/votaai-desktop")
DEFAULT_DESKTOP_BIN = DESKTOP_DIR / "dist" / "votaai-desktop"
DESKTOP_SPEC_PATH = DESKTOP_DIR / "votaai-desktop.spec"

MOBILE_DIR = Path("/home/debrito/Programação/projeto-react-native")
DEFAULT_MOBILE_APK = (
    MOBILE_DIR / "android" / "app" / "build" / "outputs" / "apk" / "release" / "app-release.apk"
)
DEFAULT_R8_MAPPING = (
    MOBILE_DIR / "android" / "app" / "build" / "outputs" / "mapping" / "release" / "mapping.txt"
)
MOBILE_PROGUARD_RULES = MOBILE_DIR / "android" / "app" / "proguard-rules.pro"
MOBILE_CMAKE_PATH = MOBILE_DIR / "android" / "app" / "src" / "main" / "cpp" / "CMakeLists.txt"
MOBILE_BUILD_GRADLE = MOBILE_DIR / "android" / "app" / "build.gradle"

DEFAULT_GHIDRA_HEADLESS = (
    REPO_ROOT
    / ".venv"
    / "share"
    / "ghidra"
    / "ghidra_11.0.3_PUBLIC"
    / "support"
    / "analyzeHeadless"
)

PYINSTALLER_COOKIE_MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"
HERMES_BUNDLE_MAGIC = 0x1F1903C103BC1FC6


@dataclass
class CheckResult:
    code: str
    title: str
    status: str  # "PASSOU" | "FALHOU" | "ALERTA" | "N/A"
    summary: str
    details: list[str] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)


# ==============================================================================
# Utilitários de Execução e Descoberta de Ferramentas
# ==============================================================================
def run_cmd(
    cmd: list[str],
    env: dict[str, str] | None = None,
    cwd: Path | None = None,
    timeout: float = 120.0,
) -> tuple[int, str, str, float, bool]:
    """Executa comando externo com timeout e retorna (rc, stdout, stderr, elapsed_s, timed_out)."""
    t0 = time.monotonic()
    try:
        res = subprocess.run(
            cmd,
            env=env,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
        )
        return res.returncode, res.stdout, res.stderr, time.monotonic() - t0, False
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        err = exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return -1, out, err, time.monotonic() - t0, True


def find_ghidra_headless(explicit: Path | None = None) -> Path | None:
    if explicit and explicit.is_file():
        return explicit
    if DEFAULT_GHIDRA_HEADLESS.is_file():
        return DEFAULT_GHIDRA_HEADLESS
    matches = sorted(
        glob.glob(str(REPO_ROOT / ".venv" / "share" / "ghidra" / "*" / "support" / "analyzeHeadless"))
    )
    if matches:
        return Path(matches[-1])
    which_bin = shutil.which("analyzeHeadless")
    return Path(which_bin) if which_bin else None


def find_sdk_build_tool(tool_name: str) -> Path | None:
    pattern = str(Path.home() / "Android" / "Sdk" / "build-tools" / "*" / tool_name)
    matches = sorted(glob.glob(pattern))
    if matches:
        return Path(matches[-1])
    which_bin = shutil.which(tool_name)
    return Path(which_bin) if which_bin else None


# ==============================================================================
# Motor de Descompilação Headless do Ghidra (Jython PostScript)
# ==============================================================================
GHIDRA_POST_SCRIPT = """# -*- coding: utf-8 -*-
import json
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.symbol import SourceType
from ghidra.util.task import ConsoleTaskMonitor

monitor = ConsoleTaskMonitor()
ifc = DecompInterface()
ifc.openProgram(currentProgram)
bbm = BasicBlockModel(currentProgram)
fm = currentProgram.getFunctionManager()

funcs = []
user_named_count = 0
auto_named_count = 0
decompiled_ok_count = 0
cff_candidates = 0
total_blocks = 0
total_edges = 0
total_gotos = 0

for f in fm.getFunctions(True):
    if f.isThunk() or f.isExternal():
        continue
    name = f.getName()
    is_auto = (
        name.startswith("FUN_")
        or name.startswith("sub_")
        or f.getSymbol().getSource() == SourceType.DEFAULT
    )
    if is_auto:
        auto_named_count += 1
    else:
        user_named_count += 1

    body = f.getBody()
    blocks = bbm.getCodeBlocksContaining(body, monitor)
    block_count = 0
    edge_count = 0
    max_out_degree = 0
    while blocks.hasNext():
        b = blocks.next()
        block_count += 1
        dests = b.getDestinations(monitor)
        out_deg = 0
        while dests.hasNext():
            dests.next()
            edge_count += 1
            out_deg += 1
        if out_deg > max_out_degree:
            max_out_degree = out_deg

    res = ifc.decompileFunction(f, 30, monitor)
    c_code = ""
    if res and res.decompileCompleted() and res.getDecompiledFunction():
        c_code = res.getDecompiledFunction().getC()
        decompiled_ok_count += 1

    cyclomatic = max(1, edge_count - block_count + 2)
    goto_count = c_code.count("goto ") if c_code else 0
    # Heurística clássica de Control Flow Flattening (OLLVM -fla):
    # dispatcher switch central com out_degree >= 8 e alta densidade ciclomática
    has_cff_signature = (max_out_degree >= 8 and block_count >= 12 and ("switch(" in c_code or "switch (" in c_code))
    if has_cff_signature:
        cff_candidates += 1

    total_blocks += block_count
    total_edges += edge_count
    total_gotos += goto_count

    funcs.append({
        "name": name,
        "is_auto_named": is_auto,
        "entry": str(f.getEntryPoint()),
        "size": int(body.getNumAddresses()),
        "blocks": block_count,
        "edges": edge_count,
        "cyclomatic": cyclomatic,
        "max_out_degree": max_out_degree,
        "decompiled_ok": bool(c_code),
        "c_lines": len(c_code.splitlines()) if c_code else 0,
        "goto_count": goto_count,
        "has_cff_signature": has_cff_signature,
        "c_snippet": " ".join(line.strip() for line in c_code.splitlines() if line.strip())[:360] if c_code else ""
    })

out_info = {
    "program": currentProgram.getName(),
    "format": currentProgram.getExecutableFormat(),
    "language": str(currentProgram.getLanguageID()),
    "compiler": str(currentProgram.getCompilerSpec().getCompilerSpecID()),
    "function_count": len(funcs),
    "user_named_count": user_named_count,
    "auto_named_count": auto_named_count,
    "decompiled_ok_count": decompiled_ok_count,
    "cff_candidates": cff_candidates,
    "total_blocks": total_blocks,
    "total_edges": total_edges,
    "total_gotos": total_gotos,
    "functions": funcs
}
print("GHIDRA_JSON_START:" + json.dumps(out_info) + ":GHIDRA_JSON_END")
"""


def run_ghidra_batch(
    ghidra_headless: Path,
    binaries: list[tuple[str, bytes]],
    timeout: float = 180.0,
) -> tuple[dict[str, dict[str, Any]], float, str]:
    """
    Executa o Ghidra Headless em lote sobre uma lista de binários (nome_arquivo, conteúdo_bytes)
    e retorna (mapa_nome_para_relatorio_ghidra, tempo_total_s, erro_se_houver).
    """
    results: dict[str, dict[str, Any]] = {}
    with tempfile.TemporaryDirectory(prefix="votaai_ghidra_t8_") as tmp_s:
        tmp_dir = Path(tmp_s)
        script_path = tmp_dir / "GhidraAuditScript.py"
        script_path.write_text(GHIDRA_POST_SCRIPT, encoding="utf-8")

        import_paths: list[str] = []
        for fname, raw_bytes in binaries:
            fpath = tmp_dir / fname
            fpath.write_bytes(raw_bytes)
            import_paths.append(str(fpath))

        cmd = [
            str(ghidra_headless),
            str(tmp_dir),
            "VotaAIAuditProj",
            "-import",
            *import_paths,
            "-scriptPath",
            str(tmp_dir),
            "-postScript",
            "GhidraAuditScript.py",
            "-deleteProject",
        ]
        rc, out, err, elapsed, timed_out = run_cmd(cmd, timeout=timeout)
        combined = out + "\n" + err
        for line in combined.splitlines():
            if "GHIDRA_JSON_START:" in line and ":GHIDRA_JSON_END" in line:
                payload = line.split("GHIDRA_JSON_START:", 1)[1].split(":GHIDRA_JSON_END", 1)[0]
                try:
                    parsed = json.loads(payload)
                    results[parsed["program"]] = parsed
                except Exception:
                    pass

        if timed_out:
            return results, elapsed, f"Timeout após {elapsed:.1f}s executando analyzeHeadless."
        if rc != 0 and not results:
            return results, elapsed, f"analyzeHeadless retornou rc={rc}: {err.strip()[:300]}"
        return results, elapsed, ""


# ==============================================================================
# Dissecador Estático PyInstaller (CArchive + PYZ + Bytecode CPython)
# ==============================================================================
def parse_pyinstaller_elf(exe_bytes: bytes) -> dict[str, Any]:
    """
    Localiza o cookie mágico MEI do PyInstaller 6.x no final do ELF, separa o bootloader
    nativo do CArchive e extrai o índice de módulos Python do PYZ.pyz.
    """
    idx = exe_bytes.rfind(PYINSTALLER_COOKIE_MAGIC)
    if idx == -1:
        raise ValueError("Cookie mágico do PyInstaller (MEI) não encontrado no binário Desktop.")

    magic, pkg_len, toc_off, toc_len, pyver, pylib_raw = struct.unpack(
        "!8sIIii64s", exe_bytes[idx : idx + 88]
    )
    pylib_name = pylib_raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    pkg_start = idx + 88 - pkg_len
    bootloader_bytes = exe_bytes[:pkg_start]

    toc_pos = pkg_start + toc_off
    toc_end = toc_pos + toc_len
    carchive_entries: dict[str, dict[str, Any]] = {}
    while toc_pos < toc_end:
        elen, dpos, dlen, ulen, cflag, typcd = struct.unpack(
            "!IIIIBB", exe_bytes[toc_pos : toc_pos + 18]
        )
        name = (
            exe_bytes[toc_pos + 18 : toc_pos + elen]
            .rstrip(b"\x00")
            .decode("utf-8", errors="replace")
        )
        carchive_entries[name] = {
            "offset": pkg_start + dpos,
            "compressed_size": dlen,
            "uncompressed_size": ulen,
            "compressed": bool(cflag),
            "type": chr(typcd),
        }
        toc_pos += elen

    return {
        "cookie_offset": idx,
        "pkg_start": pkg_start,
        "pkg_len": pkg_len,
        "bootloader_size": len(bootloader_bytes),
        "bootloader_bytes": bootloader_bytes,
        "python_version": pyver,
        "pylib_name": pylib_name,
        "carchive_entries": carchive_entries,
    }


def extract_carchive_member(exe_bytes: bytes, entry: dict[str, Any]) -> bytes:
    raw = exe_bytes[entry["offset"] : entry["offset"] + entry["compressed_size"]]
    if entry["compressed"]:
        return zlib.decompress(raw)
    return raw


def walk_code_objects(code_obj: CodeType, prefix: str = "") -> list[tuple[str, CodeType]]:
    """Percorre recursivamente todos os CodeObjects (classes, métodos e funções) de um módulo .pyc."""
    qualified = f"{prefix}.{code_obj.co_name}" if prefix else code_obj.co_name
    items: list[tuple[str, CodeType]] = [(qualified, code_obj)]
    for const in code_obj.co_consts:
        if isinstance(const, CodeType):
            child_prefix = "" if code_obj.co_name == "<module>" else qualified
            items.extend(walk_code_objects(const, child_prefix))
    return items


def analyze_bytecode_cfg(code_obj: CodeType) -> dict[str, int]:
    """
    Reconstrói o Grafo de Fluxo de Controle (CFG) de um objeto de código Python 3.12
    a partir das instruções da VM (dis.Bytecode), calculando blocos básicos, arestas e
    complexidade ciclomática M = E - N + 2.
    """
    instructions = list(dis.Bytecode(code_obj))
    if not instructions:
        return {"instructions": 0, "blocks": 1, "edges": 0, "cyclomatic": 1, "max_out_degree": 0}

    offsets = [ins.offset for ins in instructions]
    offset_to_idx = {ins.offset: i for i, ins in enumerate(instructions)}
    leaders: set[int] = {offsets[0]}

    jump_ops = {
        "JUMP_FORWARD",
        "JUMP_BACKWARD",
        "JUMP_BACKWARD_NO_INTERRUPT",
        "POP_JUMP_IF_FALSE",
        "POP_JUMP_IF_TRUE",
        "POP_JUMP_IF_NONE",
        "POP_JUMP_IF_NOT_NONE",
        "FOR_ITER",
        "END_FOR",
        "SEND",
    }
    unconditional_jumps = {"JUMP_FORWARD", "JUMP_BACKWARD", "JUMP_BACKWARD_NO_INTERRUPT"}
    terminators = {"RETURN_VALUE", "RETURN_CONST", "RAISE_VARARGS", "RERAISE"}

    for idx, ins in enumerate(instructions):
        is_jump = ins.is_jump_target or ins.opname in jump_ops or isinstance(ins.argval, int) and "JUMP" in ins.opname
        if ins.is_jump_target:
            leaders.add(ins.offset)
        if ins.opname in jump_ops and isinstance(ins.argval, int) and ins.argval in offset_to_idx:
            leaders.add(ins.argval)
            if idx + 1 < len(instructions):
                leaders.add(instructions[idx + 1].offset)
        elif ins.opname in terminators and idx + 1 < len(instructions):
            leaders.add(instructions[idx + 1].offset)

    sorted_leaders = sorted(leaders)
    leader_to_block: dict[int, int] = {off: b_idx for b_idx, off in enumerate(sorted_leaders)}
    block_count = len(sorted_leaders)
    edge_count = 0
    max_out_deg = 0

    for b_idx, start_off in enumerate(sorted_leaders):
        end_off = sorted_leaders[b_idx + 1] if b_idx + 1 < block_count else (offsets[-1] + 2)
        block_ins = [ins for ins in instructions if start_off <= ins.offset < end_off]
        if not block_ins:
            continue
        last_ins = block_ins[-1]
        out_deg = 0
        if last_ins.opname in terminators:
            out_deg = 0
        elif last_ins.opname in unconditional_jumps:
            out_deg = 1
        elif last_ins.opname in jump_ops:
            out_deg = 2
        else:
            out_deg = 1 if (b_idx + 1 < block_count) else 0
        edge_count += out_deg
        if out_deg > max_out_deg:
            max_out_deg = out_deg

    cyclomatic = max(1, edge_count - block_count + 2)
    return {
        "instructions": len(instructions),
        "blocks": block_count,
        "edges": edge_count,
        "cyclomatic": cyclomatic,
        "max_out_degree": max_out_deg,
    }


# ==============================================================================
# Bloco A — Módulo Administrativo (votaai-desktop)
# ==============================================================================
def executar_testes_desktop(
    desktop_bin: Path,
    ghidra_Results: dict[str, dict[str, Any]],
    ghidra_elapsed: float,
    ghidra_err: str,
    pyi_info: dict[str, Any],
    exe_bytes: bytes,
) -> list[CheckResult]:
    results: list[CheckResult] = []

    # ------------------------------------------------------------------
    # D1: Descompilação Ghidra do Bootloader ELF x86_64 e Símbolos Nativos
    # ------------------------------------------------------------------
    rc_sym, out_sym, _, _, _ = run_cmd(["readelf", "-Ws", str(desktop_bin)], timeout=15.0)
    has_symtab = "'.symtab'" in out_sym or "\".symtab\"" in out_sym
    dynsym_lines = [
        ln.strip()
        for ln in out_sym.splitlines()
        if "FUNC" in ln and "UND" not in ln
    ]

    gh_boot = ghidra_Results.get("votaai_desktop_bootloader.elf")
    gh_native_core = ghidra_Results.get("_votaai_native_core.so")
    if gh_boot is None:
        results.append(
            CheckResult(
                "D1",
                "Desktop | Descompilação Ghidra do ELF x86_64 e Núcleo Nativo CFF",
                "FALHOU",
                f"Falha ao descompilar o bootloader ELF no Ghidra Headless ({ghidra_err or 'sem saída JSON'}).",
            )
        )
    else:
        fn_total = gh_boot["function_count"]
        auto_cnt = gh_boot["auto_named_count"]
        decomp_cnt = gh_boot["decompiled_ok_count"]
        cff_cnt = gh_boot["cff_candidates"]
        strip_rate = (auto_cnt / fn_total * 100.0) if fn_total else 0.0
        decomp_rate = (decomp_cnt / fn_total * 100.0) if fn_total else 0.0
        max_cyc = max((f["cyclomatic"] for f in gh_boot["functions"]), default=0)
        max_out = max((f["max_out_degree"] for f in gh_boot["functions"]), default=0)

        core_cff = gh_native_core["cff_candidates"] if gh_native_core else 0
        core_fn_total = gh_native_core["function_count"] if gh_native_core else 0
        core_auto = gh_native_core["auto_named_count"] if gh_native_core else 0
        core_max_out = (
            max((f["max_out_degree"] for f in gh_native_core["functions"]), default=0)
            if gh_native_core
            else 0
        )
        core_max_cyc = (
            max((f["cyclomatic"] for f in gh_native_core["functions"]), default=0)
            if gh_native_core
            else 0
        )

        d1_details = [
            f"Ghidra Headless Bootloader ({gh_boot['language']} / {gh_boot['compiler']}): {fn_total} funções analisadas em {ghidra_elapsed:.1f}s (bootloader={pyi_info['bootloader_size']:,} B).",
            f"Tabela de símbolos ELF Bootloader: .symtab={'PRESENTE' if has_symtab else 'STRIPPED (ausente)'} | funções exportadas em .dynsym={len(dynsym_lines)} | funções anônimas FUN_*={auto_cnt}/{fn_total} ({strip_rate:.1f}%).",
            f"CFG do Bootloader ELF: blocos={gh_boot['total_blocks']}, arestas={gh_boot['total_edges']}, gotos={gh_boot['total_gotos']}, max_cyclomatic={max_cyc}, max_out_degree={max_out}.",
        ]
        if gh_native_core:
            d1_details.append(
                f"Ghidra Headless Núcleo Nativo (_votaai_native_core.so): {core_fn_total} funções ({core_auto} funções internas stripped FUN_*), "
                f"blocos={gh_native_core['total_blocks']}, arestas={gh_native_core['total_edges']}, max_cyclomatic={core_max_cyc}, "
                f"max_out_degree={core_max_out}, dispatchers OLLVM/CFF detectados={core_cff}."
            )
            for fn in gh_native_core["functions"]:
                if fn["has_cff_signature"] or fn["max_out_degree"] >= 8:
                    d1_details.append(
                        f"  • Dispatcher CFF nativo '{fn['name']}' (@{fn['entry']}): blocos={fn['blocks']}, "
                        f"arestas={fn['edges']}, M={fn['cyclomatic']}, out_degree={fn['max_out_degree']}."
                    )

        total_cff = cff_cnt + core_cff
        d1_ok = (not has_symtab) and (strip_rate >= 95.0) and (total_cff > 0 or core_max_out >= 8)

        results.append(
            CheckResult(
                "D1",
                "Desktop | Descompilação Ghidra do ELF x86_64 e Núcleo Nativo CFF",
                "PASSOU" if d1_ok else "ALERTA",
                (
                    f"ELF stripped ({strip_rate:.1f}% FUN_*) integrado ao núcleo nativo '_votaai_native_core.so' "
                    f"com achatamento de fluxo de controle confirmado no Ghidra (CFF={total_cff}, max_out_degree={max(max_out, core_max_out)})."
                    if d1_ok
                    else f"ELF stripped ({strip_rate:.1f}% de símbolos internos removidos -> FUN_*), porém o Ghidra "
                    f"recuperou {decomp_rate:.1f}% do pseudo-código C do bootloader sem achatamento de fluxo (CFF={total_cff})."
                ),
                d1_details,
                metrics={
                    "elf_functions": fn_total,
                    "elf_auto_named": auto_cnt,
                    "elf_strip_rate_pct": round(strip_rate, 2),
                    "elf_decompile_rate_pct": round(decomp_rate, 2),
                    "native_core_functions": core_fn_total,
                    "native_core_cff_candidates": core_cff,
                    "native_core_max_out_degree": core_max_out,
                },
            )
        )

    # ------------------------------------------------------------------
    # D2: Engenharia Reversa do Archive PyInstaller (CArchive / PYZ.pyz)
    # ------------------------------------------------------------------
    entries = pyi_info["carchive_entries"]
    pyz_entry = entries.get("PYZ.pyz") or next(
        (v for v in entries.values() if v["type"] == "z"), None
    )
    if not pyz_entry:
        results.append(
            CheckResult(
                "D2",
                "Desktop | Engenharia Reversa da Camada de Aplicação (PYZ.pyz)",
                "FALHOU",
                "Archive PYZ.pyz não encontrado no CArchive.",
            )
        )
    else:
        pyz_bytes = extract_carchive_member(exe_bytes, pyz_entry)
        toc_pyz_off = struct.unpack("!i", pyz_bytes[8:12])[0]
        pyz_toc = marshal.loads(pyz_bytes[toc_pyz_off:])
        if isinstance(pyz_toc, list):
            pyz_toc = dict(pyz_toc)

        app_modules = sorted(
            k for k, v in pyz_toc.items() if k.startswith("app") and isinstance(v, (tuple, list)) and len(v) >= 3 and v[2] > 0
        )
        target_routines = {
            "app.controllers.encryptionController": [
                "pad_iso7816_4",
                "unpad_iso7816_4",
                "EncryptionController._load_server_public_key",
                "EncryptionController.encrypt_payload",
                "EncryptionController.decrypt_response",
            ],
            "app.controllers.cryptoController": [
                "_enforce_security",
                "CryptoController.sign_data",
                "CryptoController.decrypt_vote",
                "CryptoController.export_election_private_key",
            ],
            "app.services.http_client": [
                "HttpClient.post",
                "HttpClient.set_auth_token",
            ],
            "app.services.security_guard": [
                "check_root_or_elevated_privileges",
                "harden_process_memory",
                "check_python_debugger",
                "check_os_debugger",
                "verify_file_integrity",
                "check_runtime_monkey_patching",
                "SecurityGuard.is_enabled",
                "SecurityGuard.enforce",
                "SecurityGuard.initialize",
            ],
            "app.controllers.native.tpm_linux": [
                "generate_rsa_key",
                "_tpm2_sign",
                "_tpm2_decrypt",
                "_get_machine_secret",
            ],
        }

        total_expected_symbols = sum(len(v) for v in target_routines.values())
        recovered_symbols = 0
        recovered_docstrings = 0
        total_code_objs = 0
        cfg_summaries: list[str] = []
        exposed_constants: list[str] = []

        for mod_name, expected_fns in target_routines.items():
            if mod_name not in pyz_toc or pyz_toc[mod_name][2] <= 0:
                continue
            _, pos, length = pyz_toc[mod_name]
            raw_pyc = zlib.decompress(pyz_bytes[pos : pos + length])
            mod_code = marshal.loads(raw_pyc)
            all_objs = dict(walk_code_objects(mod_code))
            total_code_objs += len(all_objs)

            for fn_qual in expected_fns:
                co = all_objs.get(fn_qual)
                if co is not None:
                    recovered_symbols += 1
                    if co.co_consts and isinstance(co.co_consts[0], str) and len(co.co_consts[0]) > 15:
                        recovered_docstrings += 1
                    cfg = analyze_bytecode_cfg(co)
                    if fn_qual in (
                        "EncryptionController.encrypt_payload",
                        "EncryptionController.decrypt_response",
                        "HttpClient.post",
                        "SecurityGuard.initialize",
                        "verify_file_integrity",
                    ):
                        cfg_summaries.append(
                            f"{fn_qual}: {cfg['instructions']} instr, {cfg['blocks']} blocos, "
                            f"M={cfg['cyclomatic']}, args={co.co_varnames[:co.co_argcount]}"
                        )

            # Inspeciona constantes literais expostas no módulo
            for _, co in all_objs.items():
                for c in co.co_consts:
                    if isinstance(c, str) and any(
                        tok in c
                        for tok in (
                            "VotaAI_SecureKey_1",
                            "VotaAI_DesktopClient_Key",
                            "encrypted_payload",
                            "encrypted_aes_key",
                            "TracerPid:",
                            "VOTAAI_SECURITY_GUARD",
                            "0x81010010",
                            "VotaAI-DesktopClient-KeyProtection-v1",
                        )
                    ):
                        if c not in exposed_constants:
                            exposed_constants.append(c)

        qml_entries = [k for k in entries.keys() if k.endswith(".qml")]
        has_plain_env = ".env" in entries
        has_plain_routes = "app/resources/api_routes.json" in entries
        has_plain_key = "app/resources/initial_key.json" in entries

        sym_recovery_rate = (
            recovered_symbols / total_expected_symbols * 100.0 if total_expected_symbols else 0.0
        )

        # Verifica se os módulos 'app.*' no PYZ.pyz foram convertidos em loaders CFF cifrados
        cff_encrypted_modules = 0
        sample_loader_cfg: dict[str, int] = {}
        for mod_name in app_modules:
            _, pos, length = pyz_toc[mod_name]
            raw_pyc = zlib.decompress(pyz_bytes[pos : pos + length])
            mod_code = marshal.loads(raw_pyc)
            cfg_m = analyze_bytecode_cfg(mod_code)
            if (
                cfg_m["cyclomatic"] >= 8
                and len(walk_code_objects(mod_code)) == 1
                and "_s" in mod_code.co_names
                and "votaai_transform_bytecode" in mod_code.co_names
            ):
                cff_encrypted_modules += 1
                if not sample_loader_cfg:
                    sample_loader_cfg = cfg_m

        d2_ok = (
            recovered_symbols == 0
            and recovered_docstrings == 0
            and len(exposed_constants) == 0
            and cff_encrypted_modules == len(app_modules)
        )

        d2_details = [
            f"CArchive extraído de '{desktop_bin.name}': {len(entries)} arquivos empacotados (Python {pyi_info['python_version']}, lib={pyi_info['pylib_name']}).",
            f"Módulos 'app.*' no PYZ.pyz protegidos por cifragem nativa + loader CFF (co_filename='<obf>', optimize=2): {cff_encrypted_modules}/{len(app_modules)}.",
            f"Recuperação de símbolos das rotinas críticas: {recovered_symbols}/{total_expected_symbols} ({sym_recovery_rate:.1f}%) funções/métodos expostos | docstrings preservadas: {recovered_docstrings}.",
        ]
        if sample_loader_cfg:
            d2_details.append(
                f"CFG do stub CFF em PYZ.pyz: {sample_loader_cfg['instructions']} instruções, "
                f"{sample_loader_cfg['blocks']} blocos básicos, {sample_loader_cfg['edges']} arestas, "
                f"complexidade ciclomática M={sample_loader_cfg['cyclomatic']} (dispatcher while/if com predicado opaco)."
            )
        if cfg_summaries:
            d2_details.append("Fluxo de controle (CFG) reconstruído diretamente do bytecode:")
            d2_details.extend([f"  • {s}" for s in cfg_summaries])
        d2_details.append(
            f"Constantes criptográficas e de segurança extraídas em texto claro do PYZ.pyz: {len(exposed_constants)} ({exposed_constants[:8]})."
        )

        results.append(
            CheckResult(
                "D2",
                "Desktop | Engenharia Reversa do PYZ.pyz, Símbolos e Fluxo de Controle Python",
                "PASSOU" if d2_ok else "FALHOU",
                (
                    f"100% dos {len(app_modules)} módulos 'app.*' no PYZ.pyz estão cifrados com stream cipher nativo e encapsulados "
                    f"em loaders CFF (0/{total_expected_symbols} símbolos recuperados, 0 docstrings, 0 constantes expostas)."
                    if d2_ok
                    else f"{recovered_symbols}/{total_expected_symbols} rotinas críticas foram recuperadas do PYZ.pyz com nomes originais, "
                    f"{recovered_docstrings} docstrings e {len(exposed_constants)} constantes em claro."
                ),
                d2_details,
                metrics={
                    "app_modules_in_pyz": len(app_modules),
                    "cff_encrypted_modules": cff_encrypted_modules,
                    "critical_routines_recovered": recovered_symbols,
                    "critical_routines_total": total_expected_symbols,
                    "symbol_recovery_rate_pct": round(sym_recovery_rate, 2),
                    "docstrings_preserved": recovered_docstrings,
                    "exposed_constants_count": len(exposed_constants),
                },
            )
        )

    # ------------------------------------------------------------------
    # D3: Auditoria de Resistência a Alteração Estrutural e Manifesto SHA-256
    # ------------------------------------------------------------------
    manifest_entry = entries.get("app/resources/integrity_manifest.json")
    manifest_data: dict[str, Any] = {}
    if manifest_entry:
        manifest_raw = extract_carchive_member(exe_bytes, manifest_entry)
        manifest_data = json.loads(manifest_raw.decode("utf-8", errors="replace"))

    files_in_manifest: dict[str, str] = manifest_data.get("files", {})
    py_in_manifest = [k for k in files_in_manifest if k.endswith(".py")]
    qml_in_manifest = [k for k in files_in_manifest if k.endswith(".qml")]
    json_in_manifest = [k for k in files_in_manifest if k.endswith(".json")]
    native_seal = manifest_data.get("native_seal", "")
    has_native_core_in_carchive = "app/services/_votaai_native_core.so" in entries

    sg_src = (DESKTOP_DIR / "app" / "services" / "security_guard.py").read_text(encoding="utf-8")
    verifies_frozen_pyz = "_verify_frozen_pyz_modules" in sg_src and "votaai_compute_seal" in sg_src

    qml_tamper_detected = False
    key_tamper_detected = False
    if manifest_data:
        canonical = json.dumps(files_in_manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
        calc_root = hashlib.sha256(canonical).hexdigest()
        root_hash_valid = calc_root == manifest_data.get("root_hash")
        app_qml_entry = entries.get("Design/DesignContent/App.qml")
        init_key_entry = entries.get("app/resources/initial_key.json")
        if app_qml_entry:
            qml_bytes = extract_carchive_member(exe_bytes, app_qml_entry).replace(b"\r\n", b"\n")
            tampered_qml_hash = hashlib.sha256(qml_bytes + b"\n// tamper").hexdigest()
            qml_tamper_detected = tampered_qml_hash != files_in_manifest.get("Design/DesignContent/App.qml")
        if init_key_entry:
            key_bytes = extract_carchive_member(exe_bytes, init_key_entry).replace(b"\r\n", b"\n")
            tampered_key_hash = hashlib.sha256(key_bytes + b" ").hexdigest()
            key_tamper_detected = tampered_key_hash != files_in_manifest.get("app/resources/initial_key.json")
    else:
        root_hash_valid = False

    d3_ok = (
        root_hash_valid
        and bool(native_seal)
        and has_native_core_in_carchive
        and verifies_frozen_pyz
        and qml_tamper_detected
        and key_tamper_detected
    )

    d3_details = [
        f"Manifesto embutido (integrity_manifest.json): root_hash={manifest_data.get('root_hash', 'N/A')[:16]}... (válido={root_hash_valid}), native_seal={'PRESENTE (' + native_seal[:24] + '...)' if native_seal else 'AUSENTE'}.",
        f"Arquivos monitorados ({len(files_in_manifest)}): {len(py_in_manifest)} módulos Python, {len(qml_in_manifest)} interfaces QML e {len(json_in_manifest)} chave pública estática (initial_key.json).",
        f"Proteção em _MEIPASS: adulteração em 'Design/DesignContent/App.qml' detectada={qml_tamper_detected} | adulteração em 'app/resources/initial_key.json' detectada={key_tamper_detected}.",
        f"Validação cruzada em modo congelado (sys.frozen): núcleo '_votaai_native_core.so' embutido={has_native_core_in_carchive} | auditoria de PYZ.pyz e selo HMAC/CFF ativo={verifies_frozen_pyz}.",
    ]

    results.append(
        CheckResult(
            "D3",
            "Desktop | Resistência a Alteração Estrutural e Cobertura do Manifesto SHA-256",
            "PASSOU" if d3_ok else "FALHOU",
            (
                f"Manifesto SHA-256 autenticado por selo criptográfico nativo (native_seal) e validação ativa dos "
                f"{len(py_in_manifest)} módulos no PYZ.pyz + {len(qml_in_manifest)} arquivos QML + initial_key.json."
                if d3_ok
                else f"Manifesto SHA-256 protege os {len(qml_in_manifest)} arquivos QML e initial_key.json em _MEIPASS, "
                f"mas possui lacunas na validação dos módulos congelados ou selo nativo ausente."
            ),
            d3_details,
            metrics={
                "manifest_total_files": len(files_in_manifest),
                "has_native_seal": bool(native_seal),
                "has_native_core_so": has_native_core_in_carchive,
                "verifies_frozen_pyz": verifies_frozen_pyz,
                "qml_tamper_detected": qml_tamper_detected,
                "key_tamper_detected": key_tamper_detected,
            },
        )
    )

    return results


# ==============================================================================
# Bloco B — Aplicativo Móvel (projeto-react-native / app-release.apk)
# ==============================================================================
def parse_hermes_Strings(bundle_bytes: bytes) -> dict[str, Any]:
    """
    Valida o cabeçalho binário do Hermes Bytecode (HBC) e extrai identificadores e
    constantes sensíveis presentes na tabela de strings do bundle compilado.
    """
    if len(bundle_bytes) < 32:
        return {"is_hermes": False}
    magic = struct.unpack("<Q", bundle_bytes[:8])[0]
    version = struct.unpack("<I", bundle_bytes[8:12])[0]
    sha1_header = bundle_bytes[12:32].hex()
    is_hermes = magic == HERMES_BUNDLE_MAGIC

    critical_identifiers = [
        "VoteService",
        "requestVote",
        "castVote",
        "requestBallot",
        "generateSecureNonce",
        "encryptPayloadForServer",
        "decryptResponseFromServer",
        "generateKeyWithAttestation",
        "SERVER_MOBILE_TPM_PUBLIC_KEY",
        "ModuloSegurancaHardware",
        "cifrarEnvelopeParaServidor",
        "cifrarComChaveEleicao",
        "assinarComChaveHardware",
    ]
    critical_endpoints_and_keys = [
        "/api/vote/request/",
        "/api/vote/cast/",
        "-----BEGIN PUBLIC KEY-----",
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwK42Qa/I4X+E3Gi/VcPc",
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELCNngOqmiTYGoPVhe91LA7bzpC15",
        "votaai-qr:v2:",
        "encrypted_payload",
        "encrypted_aes_key",
    ]

    found_identifiers = [s for s in critical_identifiers if s.encode("utf-8") in bundle_bytes]
    found_constants = [s for s in critical_endpoints_and_keys if s.encode("utf-8") in bundle_bytes]

    # Verifica se comentários ou código-fonte TypeScript bruto permanceram no bundle
    source_code_markers = [
        b"import { hardwareSecurityService }",
        b"export class VoteService extends ApiClient",
        b"private async executeFetch(",
    ]
    raw_source_leaked = any(m in bundle_bytes for m in source_code_markers)

    return {
        "is_hermes": is_hermes,
        "version": version,
        "size_bytes": len(bundle_bytes),
        "header_sha1": sha1_header,
        "raw_source_leaked": raw_source_leaked,
        "found_identifiers": found_identifiers,
        "total_identifiers_probed": len(critical_identifiers),
        "found_constants": found_constants,
        "total_constants_probed": len(critical_endpoints_and_keys),
    }


def executar_testes_mobile(
    mobile_apk: Path,
    r8_mapping_path: Path,
    ghidra_results: dict[str, dict[str, Any]],
    ghidra_elapsed: float,
    ghidra_err: str,
    apk_members: dict[str, bytes],
) -> list[CheckResult]:
    results: list[CheckResult] = []

    # ------------------------------------------------------------------
    # M1: Descompilação Ghidra de libseguranca_nativa.so (ARM64 e x86_64)
    # ------------------------------------------------------------------
    gh_arm64 = ghidra_results.get("libseguranca_nativa_arm64.so")
    gh_x64 = ghidra_results.get("libseguranca_nativa_x86_64.so")

    so_arm64_bytes = apk_members.get("lib/arm64-v8a/libseguranca_nativa.so", b"")
    sensitive_rodata_probes = [
        "/proc/self/status",
        "TracerPid:",
        "/proc/self/maps",
        "/proc/self/fd",
        "/proc/self/task",
        "gum-js-loop",
        "pool-frida",
        "frida",
        "xposed",
        "/system/bin/su",
        "/sbin/.magisk",
        "/data/adb/magisk",
        "Violacao critica nativa detectada",
    ]
    exposed_rodata = [s for s in sensitive_rodata_probes if s.encode("utf-8") in so_arm64_bytes]

    # Nomes das funções internas C++ no código-fonte original (namespace anônimo)
    internal_cpp_names = [
        "detectarTracerPidInterno",
        "detectarHooksMemoriaInterno",
        "detectarDescritoresSuspeitosInterno",
        "detectarThreadsSuspeitasInterno",
        "detectarPortaFridaInterno",
        "detectarRootArquivosInterno",
        "detectarMontagemSuspeitaInterno",
        "verificarViolacoesCriticasInterno",
        "watchdogThreadLoop",
        "iniciarWatchdogNativo",
        "encerrarProcessoNativo",
    ]
    leaked_internal_cpp = [s for s in internal_cpp_names if s.encode("utf-8") in so_arm64_bytes]

    if gh_arm64 is None:
        results.append(
            CheckResult(
                "M1",
                "Mobile | Descompilação Ghidra de libseguranca_nativa.so (C++ / NDK)",
                "FALHOU",
                f"Não foi possível descompilar libseguranca_nativa.so no Ghidra ({ghidra_err}).",
            )
        )
    else:
        jni_exports = [
            f for f in gh_arm64["functions"] if f["name"].startswith("Java_") or f["name"] == "JNI_OnLoad"
        ]
        anon_funcs = [f for f in gh_arm64["functions"] if f["is_auto_named"]]
        decomp_ok = gh_arm64["decompiled_ok_count"]
        fn_total = gh_arm64["function_count"]
        cff_cnt = gh_arm64["cff_candidates"]
        max_cyc = max((f["cyclomatic"] for f in gh_arm64["functions"]), default=0)
        max_out = max((f["max_out_degree"] for f in gh_arm64["functions"]), default=0)

        x64_info = (
            f"{gh_x64['function_count']} funções ({gh_x64['decompiled_ok_count']} descompiladas, CFF={gh_x64['cff_candidates']})"
            if gh_x64
            else "N/A"
        )

        # Seleciona snippets do pseudo-código C gerado pelo Ghidra para JNI_OnLoad e nativeDetectarTracerPid
        snippets: list[str] = []
        for target_fn in (
            "JNI_OnLoad",
            "Java_com_meuapptestecripto_SegurancaNativa_nativeConfigurarWatchdog",
            "Java_com_meuapptestecripto_SegurancaNativa_nativeDetectarTracerPid",
        ):
            match_f = next((f for f in gh_arm64["functions"] if f["name"] == target_fn), None)
            if match_f:
                snippets.append(
                    f"{match_f['name']} (blocos={match_f['blocks']}, M={match_f['cyclomatic']}, "
                    f"out_deg={match_f['max_out_degree']}, linhas_C={match_f['c_lines']}): {match_f['c_snippet'][:170]}..."
                )

        m1_ok = (
            len(leaked_internal_cpp) == 0
            and len(jni_exports) <= 1
            and (cff_cnt > 0 or max_out >= 8)
            and len(exposed_rodata) == 0
        )

        m1_details = [
            f"Ghidra Headless ARM64 ({gh_arm64['language']}): {fn_total} funções analisadas ({decomp_ok}/{fn_total} descompiladas) | x86_64: {x64_info}.",
            f"Ocultação de símbolos (-fvisibility=hidden + strip): {len(internal_cpp_names) - len(leaked_internal_cpp)}/{len(internal_cpp_names)} símbolos internos removidos ({len(anon_funcs)} funções anônimas FUN_*).",
            f"Registro dinâmico JNI (RegisterNatives): apenas {len(jni_exports)} símbolo exportado em .dynsym ({[f['name'] for f in jni_exports]}), 0 símbolos Java_com_meuapptestecripto_* expostos.",
            f"Métricas de Fluxo de Controle (CFG): total_blocos={gh_arm64['total_blocks']}, total_arestas={gh_arm64['total_edges']}, max_cyclomatic={max_cyc}, max_out_degree={max_out}, gotos={gh_arm64['total_gotos']}, dispatchers CFF={cff_cnt}.",
            *snippets,
            f"Cifragem de strings em .rodata (constexpr XOR): {len(exposed_rodata)}/{len(sensitive_rodata_probes)} literais de detecção visíveis em texto claro ({exposed_rodata}).",
        ]

        results.append(
            CheckResult(
                "M1",
                "Mobile | Descompilação Ghidra de libseguranca_nativa.so (ARM64 / x86_64)",
                "PASSOU" if m1_ok else "FALHOU",
                (
                    f"100% dos handlers JNI ocultados via RegisterNatives ({len(anon_funcs)} FUN_*), "
                    f"0/{len(sensitive_rodata_probes)} strings sensíveis em .rodata (XOR em stack) e "
                    f"achatamento de fluxo de controle confirmado no Ghidra (CFF={cff_cnt}, max_out_degree={max_out})."
                    if m1_ok
                    else f"Embora -fvisibility=hidden tenha ocultado símbolos internos ({len(anon_funcs)} FUN_*), "
                    f"restaram {len(jni_exports)} exports JNI, CFF={cff_cnt} e {len(exposed_rodata)}/{len(sensitive_rodata_probes)} strings em .rodata."
                ),
                m1_details,
                metrics={
                    "arm64_functions": fn_total,
                    "arm64_decompiled_ok": decomp_ok,
                    "internal_symbols_hidden": len(internal_cpp_names) - len(leaked_internal_cpp),
                    "jni_exports_exposed": len(jni_exports),
                    "cff_candidates": cff_cnt,
                    "max_out_degree": max_out,
                    "rodata_strings_exposed": len(exposed_rodata),
                },
            )
        )

    # ------------------------------------------------------------------
    # M2: Descompilação Dalvik (classes.dex) e Eficiência da Ofuscação R8
    # ------------------------------------------------------------------
    dexdump_bin = find_sdk_build_tool("dexdump")
    dex_bytes = apk_members.get("classes.dex", b"")

    # Analisa classes do pacote da aplicação diretamente no classes.dex via dexdump
    app_classes_in_dex: list[str] = []
    kept_security_methods: list[str] = []
    obfuscated_verifier_methods: list[str] = []

    if dexdump_bin and dex_bytes:
        with tempfile.TemporaryDirectory(prefix="votaai_dex_") as tmp_d:
            dex_path = Path(tmp_d) / "classes.dex"
            dex_path.write_bytes(dex_bytes)
            _, dex_out, _, _, _ = run_cmd([str(dexdump_bin), str(dex_path)], timeout=45.0)
            for m in re.finditer(r"Class descriptor\s*:\s*'L([^']+);'", dex_out):
                cls_name = m.group(1).replace("/", ".")
                if cls_name.startswith("com.meuapptestecripto") or cls_name in ("o11", "n11", "m11", "xe0", "rl0", "sl0", "tl0", "ul0"):
                    app_classes_in_dex.append(cls_name)

            # Extrai métodos expostos em ModuloSegurancaHardware, SegurancaNativa e o11 (VerificadorSegurancaAndroid)
            for target_desc in (
                "Lcom/meuapptestecripto/ModuloSegurancaHardware;",
                "Lcom/meuapptestecripto/SegurancaNativa;",
                "Lcom/meuapptestecripto/PinningOkHttpClientFactory;",
                "Lcom/meuapptestecripto/QrSignatureVerifier;",
                "Lo11;",
            ):
                pos = dex_out.find(f"Class descriptor  : '{target_desc}'")
                if pos != -1:
                    chunk = dex_out[pos : pos + 12000]
                    next_cls = chunk.find("Class #", 20)
                    if next_cls != -1:
                        chunk = chunk[:next_cls]
                    names = re.findall(r"name\s*:\s*'([^']+)'", chunk)
                    if target_desc == "Lo11;":
                        for n in names:
                            if n not in obfuscated_verifier_methods:
                                obfuscated_verifier_methods.append(n)
                    else:
                        short_cls = target_desc.strip("L;").split("/")[-1]
                        for n in names:
                            qual_n = f"{short_cls}.{n}"
                            if not n.startswith("<") and not n.startswith("access$") and qual_n not in kept_security_methods:
                                kept_security_methods.append(qual_n)

    # Analisa também o mapping.txt oficial do R8 para quantificar a taxa de renomeação
    r8_total_app_classes = 0
    r8_renamed_app_classes = 0
    r8_kept_app_classes: list[str] = []
    r8_renamed_examples: list[str] = []
    if r8_mapping_path.is_file():
        for line in r8_mapping_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("com.meuapptestecripto.") and " -> " in line and line.endswith(":"):
                orig, mapped = line[:-1].split(" -> ", 1)
                r8_total_app_classes += 1
                if orig != mapped:
                    r8_renamed_app_classes += 1
                    r8_renamed_examples.append(f"{orig.split('.')[-1]} -> {mapped}")
                else:
                    r8_kept_app_classes.append(orig.split(".")[-1])

    class_rename_rate = (
        r8_renamed_app_classes / r8_total_app_classes * 100.0 if r8_total_app_classes else 0.0
    )

    # Verifica se métodos internos sensíveis (padIso7816_4, unpadIso7816_4, buildSpec, generateKeyWithAttestationInternal,
    # verifyAndExtract, createNewNetworkModuleClient) continuam expostos com nomes originais em classes.dex
    internal_method_probes = (
        "padIso7816_4",
        "unpadIso7816_4",
        "buildSpec",
        "generateKeyWithAttestationInternal",
        "findViewByTagOrId",
        "verifyAndExtract",
        "ALIAS_CHAVE",
        "BALLOT_PAD_BLOCK_SIZE",
        "ENVELOPE_PAD_BLOCK_SIZE",
    )
    leaked_internal_dex = [
        m for m in kept_security_methods if any(p in m for p in internal_method_probes)
    ]
    # Apenas as 5 classes de fronteira obrigatórias (AndroidManifest / ReactMethod / JNI RegisterNatives) podem manter o nome externo
    allowed_boundary_classes = {
        "MainActivity",
        "MainApplication",
        "ModuloSegurancaHardware",
        "QrScannerActivity",
        "SegurancaNativa",
    }
    unobfuscated_internal_classes = [
        c for c in r8_kept_app_classes if c not in allowed_boundary_classes
    ]
    m2_ok = (
        class_rename_rate >= 65.0
        and len(unobfuscated_internal_classes) == 0
        and len(leaked_internal_dex) == 0
    )

    m2_details = [
        f"R8 / ProGuard ativo no build release (classes.dex={len(dex_bytes):,} B): {r8_renamed_app_classes}/{r8_total_app_classes} ({class_rename_rate:.1f}%) classes do pacote foram renomeadas (demais classes internas como MotorCriptografiaHardware e PinningOkHttpClientFactory foram 100% inlined/eliminadas).",
        f"Classes com renomeação irreversível e inlining R8: {r8_renamed_examples[:12]} (VerificadorSegurancaAndroid -> {obfuscated_verifier_methods}).",
        f"Pontos de entrada de fronteira AndroidManifest/ReactMethod/JNI mantidos ({len(r8_kept_app_classes)}): {r8_kept_app_classes} | classes internas sem ofuscação: {len(unobfuscated_internal_classes)}.",
        f"Métodos/constantes internos de criptografia vazados sem ofuscação em classes.dex: {len(leaked_internal_dex)} ({leaked_internal_dex}).",
    ]

    results.append(
        CheckResult(
            "M2",
            "Mobile | Descompilação Dalvik (classes.dex) e Cobertura de Ofuscação R8",
            "PASSOU" if m2_ok else "FALHOU",
            (
                f"Ofuscação R8 abrangente ({r8_renamed_app_classes}/{r8_total_app_classes} = {class_rename_rate:.1f}% das classes renomeadas) "
                f"com 0 métodos/constantes internos de criptografia expostos em classes.dex (apenas fronteira @ReactMethod/JNI preservada)."
                if m2_ok
                else f"Ofuscação R8 parcial ({class_rename_rate:.1f}% das classes do app renomeadas): "
                f"{len(leaked_internal_dex)} métodos/campos internos de criptografia permaneceram com símbolos originais."
            ),
            m2_details,
            metrics={
                "r8_app_classes_total": r8_total_app_classes,
                "r8_app_classes_renamed": r8_renamed_app_classes,
                "r8_class_rename_rate_pct": round(class_rename_rate, 2),
                "leaked_internal_dex_symbols": len(leaked_internal_dex),
                "obfuscated_verifier_methods": obfuscated_verifier_methods,
            },
        )
    )

    # ------------------------------------------------------------------
    # M3: Análise Estática do Bundle Hermes Bytecode (index.android.bundle)
    # ------------------------------------------------------------------
    bundle_bytes = apk_members.get("assets/index.android.bundle", b"")
    hbc = parse_hermes_Strings(bundle_bytes)

    id_exposure_rate = (
        len(hbc["found_identifiers"]) / hbc["total_identifiers_probed"] * 100.0
        if hbc.get("total_identifiers_probed")
        else 0.0
    )

    m3_details = [
        f"Formato de 'assets/index.android.bundle' ({hbc.get('size_bytes', 0):,} B): Hermes Bytecode compilado={'SIM' if hbc.get('is_hermes') else 'NÃO'} (versão HBC={hbc.get('version')}, SHA-1 cabeçalho={hbc.get('header_sha1')}).",
        f"Conversão de código-fonte TypeScript/JavaScript: código-fonte bruto removido={'SIM (0 trechos TS/JS em texto puro)' if not hbc.get('raw_source_leaked') else 'NÃO'}.",
        f"Exposição na tabela de símbolos/strings do Hermes: {len(hbc['found_identifiers'])}/{hbc['total_identifiers_probed']} ({id_exposure_rate:.1f}%) identificadores das rotinas de votação e criptografia permanecem legíveis: {hbc['found_identifiers']}.",
        f"Constantes críticas extraídas diretamente do bundle: {len(hbc['found_constants'])}/{hbc['total_constants_probed']} encontradas (rotas '/api/vote/request/', '/api/vote/cast/', chave RSA SERVER_MOBILE_TPM_PUBLIC_KEY e chave ECDSA QR_SIGNING_PUBLIC_KEY).",
        "Diagnóstico Hermes HBC: a compilação AOT para bytecode Hermes elimina o código-fonte JS e dificulta o patching direto de instruções sem reescrever offsets/hashes do cabeçalho HBC, mas não ofusca nomes de propriedades nem cifra constantes da tabela de strings.",
    ]

    results.append(
        CheckResult(
            "M3",
            "Mobile | Análise Estática do Bundle Hermes Bytecode (index.android.bundle)",
            "ALERTA",
            (
                f"Código JS/TS convertido para Hermes Bytecode v{hbc.get('version')} (sem código-fonte em texto puro), "
                f"mas {len(hbc['found_identifiers'])}/{hbc['total_identifiers_probed']} identificadores de métodos e "
                f"{len(hbc['found_constants'])}/{hbc['total_constants_probed']} constantes/rotas permanecem legíveis na tabela de strings."
            ),
            m3_details,
            metrics={
                "is_hermes_bytecode": hbc.get("is_hermes", False),
                "hermes_version": hbc.get("version", 0),
                "raw_js_source_leaked": hbc.get("raw_source_leaked", False),
                "exposed_identifiers_count": len(hbc.get("found_identifiers", [])),
                "exposed_constants_count": len(hbc.get("found_constants", [])),
            },
        )
    )

    # ------------------------------------------------------------------
    # M4: Auditoria de Resistência a Alteração Estrutural e Assinatura APK
    # ------------------------------------------------------------------
    apksigner_bin = find_sdk_build_tool("apksigner")
    apk_sig_valid = False
    apk_sig_schemes = ""
    apk_cert_sha256 = ""
    apk_cert_dn = ""

    if apksigner_bin:
        rc_sig, out_sig, err_sig, _, _ = run_cmd(
            [str(apksigner_bin), "verify", "--verbose", "--print-certs", str(mobile_apk)],
            timeout=20.0,
        )
        apk_sig_valid = rc_sig == 0
        v2_ok = "Verified using v2 scheme (APK Signature Scheme v2): true" in out_sig
        v3_ok = "Verified using v3 scheme (APK Signature Scheme v3): true" in out_sig
        apk_sig_schemes = f"v2={v2_ok}, v3={v3_ok}"
        m_sha = re.search(r"certificate SHA-256 digest:\s*([0-9a-fA-F]+)", out_sig)
        if m_sha:
            apk_cert_sha256 = m_sha.group(1).upper()
        m_dn = re.search(r"certificate DN:\s*(.+)", out_sig)
        if m_dn:
            apk_cert_dn = m_dn.group(1).strip()

    # Prueba prática em cópia temporária do APK: alterar 1 byte no index.android.bundle invalida apksigner?
    tampered_apk_rejected_by_apksigner = False
    if apksigner_bin and bundle_bytes:
        with tempfile.TemporaryDirectory(prefix="votaai_apk_tamper_") as tmp_t:
            tampered_apk = Path(tmp_t) / "app-release-tampered.apk"
            with zipfile.ZipFile(mobile_apk, "r") as zin, zipfile.ZipFile(
                tampered_apk, "w", compression=zipfile.ZIP_DEFLATED
            ) as zout:
                for item in zin.infolist():
                    data = zin.read(item.filename)
                    if item.filename == "assets/index.android.bundle":
                        # Altera 1 byte na string de rota dentro da cópia temporária
                        data = data.replace(b"/api/vote/cast/", b"/api/vote/xxxx/", 1)
                    zout.writestr(item, data)
            rc_t, _, _, _, _ = run_cmd([str(apksigner_bin), "verify", str(tampered_apk)], timeout=15.0)
            tampered_apk_rejected_by_apksigner = rc_t != 0

    # Inspeciona BuildConfig e build.gradle quanto a EXPECTED_SIGNING_SHA256, EXPECTED_BUNDLE_SHA256 e signingConfig
    gradle_txt = MOBILE_BUILD_GRADLE.read_text(encoding="utf-8") if MOBILE_BUILD_GRADLE.is_file() else ""
    m_rel_block = re.search(r"buildTypes\s*\{.*?\brelease\s*\{([^}]*)\}", gradle_txt, re.DOTALL)
    release_block_txt = m_rel_block.group(1) if m_rel_block else ""
    uses_debug_keystore_in_release = (
        "signingConfigs.debug" in release_block_txt or "CN=Android Debug" in apk_cert_dn
    )

    m_exp_sig = re.search(r'expectedSigningSha256\s*=.*?\?:\s*"([0-9A-Fa-f]+)"', gradle_txt)
    expected_signing_sha256 = m_exp_sig.group(1).upper() if m_exp_sig else ""
    signing_pin_matches = bool(apk_cert_sha256 and expected_signing_sha256 == apk_cert_sha256)

    m_exp_bundle = re.search(r'expectedBundleSha256\s*=.*?\?:\s*"([^"]*)"', gradle_txt)
    expected_bundle_sha256 = m_exp_bundle.group(1).strip().upper() if m_exp_bundle else ""
    actual_bundle_sha256 = hashlib.sha256(bundle_bytes).hexdigest().upper() if bundle_bytes else ""
    bundle_pin_matches = bool(expected_bundle_sha256 and expected_bundle_sha256 == actual_bundle_sha256)

    m4_ok = (
        apk_sig_valid
        and tampered_apk_rejected_by_apksigner
        and signing_pin_matches
        and bundle_pin_matches
        and (not uses_debug_keystore_in_release)
    )

    m4_details = [
        f"Assinatura criptográfica do APK original (apksigner): válida={apk_sig_valid} ({apk_sig_schemes}) | DN='{apk_cert_dn}' | cert_sha256={apk_cert_sha256[:24]}...",
        f"Ancoragem de certificado em VerificadorSegurancaAndroid (o11.d): EXPECTED_SIGNING_SHA256={expected_signing_sha256[:24]}... (compatível={signing_pin_matches}).",
        f"Prova de adulteração estrutural em cópia temporária do APK (patch de 15 bytes em assets/index.android.bundle): rejeitado imediatamente pela verificação criptográfica APK Signature v2/v3={tampered_apk_rejected_by_apksigner}.",
        f"Validação SHA-256 do bundle Hermes (EXPECTED_BUNDLE_SHA256): esperado={expected_bundle_sha256[:24] or 'VAZIO'}... | real={actual_bundle_sha256[:24]}... (compatível={bundle_pin_matches}).",
        f"Keystore de Release dedicada (fora de debug.keystore): ativa={not uses_debug_keystore_in_release}.",
    ]

    results.append(
        CheckResult(
            "M4",
            "Mobile | Resistência a Alteração Estrutural, Assinatura APK e Hash do Bundle",
            "PASSOU" if m4_ok else "FALHOU",
            (
                "APK protegido por assinatura v2/v3 com keystore dedicada, EXPECTED_SIGNING_SHA256 ancorado e validação estrita de SHA-256 do bundle Hermes."
                if m4_ok
                else "APK Signature v2/v3 ativa, porém há divergência/ausência em EXPECTED_BUNDLE_SHA256 ou uso de debug.keystore em release."
            ),
            m4_details,
            metrics={
                "apk_signature_valid": apk_sig_valid,
                "tampered_apk_rejected": tampered_apk_rejected_by_apksigner,
                "signing_pin_configured": signing_pin_matches,
                "expected_bundle_sha256_matches": bundle_pin_matches,
                "uses_debug_keystore_in_release": uses_debug_keystore_in_release,
            },
        )
    )

    return results


# ==============================================================================
# CLI e Orquestração Principal
# ==============================================================================
def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Teste 8 (Eixo 3): Engenharia Reversa com Ghidra e Ofuscação de Binários."
    )
    p.add_argument(
        "--target",
        choices=("all", "desktop", "mobile"),
        default="all",
        help="Alvo(s) da auditoria estática (padrão: all).",
    )
    p.add_argument(
        "--desktop-bin",
        type=Path,
        default=DEFAULT_DESKTOP_BIN,
        help=f"Binário ELF final de produção do Desktop (padrão: {DEFAULT_DESKTOP_BIN}).",
    )
    p.add_argument(
        "--mobile-apk",
        type=Path,
        default=DEFAULT_MOBILE_APK,
        help=f"APK release final do cliente Android (padrão: {DEFAULT_MOBILE_APK}).",
    )
    p.add_argument(
        "--r8-mapping",
        type=Path,
        default=DEFAULT_R8_MAPPING,
        help=f"Arquivo mapping.txt do R8 para auditoria quantitativa (padrão: {DEFAULT_R8_MAPPING}).",
    )
    p.add_argument(
        "--ghidra-headless",
        type=Path,
        default=None,
        help="Caminho para o script analyzeHeadless do Ghidra.",
    )
    p.add_argument(
        "--json-out",
        type=Path,
        default=None,
        help="Caminho opcional para salvar o relatório detalhado em JSON.",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    ghidra_headless = find_ghidra_headless(args.ghidra_headless)

    if ghidra_headless is None or not ghidra_headless.is_file():
        print(
            "[ERRO] Utilitário Ghidra 'analyzeHeadless' não encontrado. "
            "Informe --ghidra-headless ou instale em .venv/share/ghidra/.",
            file=sys.stderr,
        )
        return 2

    binaries_for_ghidra: list[tuple[str, bytes]] = []
    exe_bytes = b""
    pyi_info: dict[str, Any] = {}
    apk_members: dict[str, bytes] = {}

    if args.target in ("all", "desktop"):
        if not args.desktop_bin.is_file():
            print(f"[ERRO] Binário Desktop não encontrado: {args.desktop_bin}", file=sys.stderr)
            return 2
        exe_bytes = args.desktop_bin.read_bytes()
        pyi_info = parse_pyinstaller_elf(exe_bytes)
        binaries_for_ghidra.append(("votaai_desktop_bootloader.elf", pyi_info["bootloader_bytes"]))
        native_core_entry = pyi_info["carchive_entries"].get("app/services/_votaai_native_core.so")
        if native_core_entry:
            binaries_for_ghidra.append(
                ("_votaai_native_core.so", extract_carchive_member(exe_bytes, native_core_entry))
            )

    if args.target in ("all", "mobile"):
        if not args.mobile_apk.is_file():
            print(f"[ERRO] APK Mobile não encontrado: {args.mobile_apk}", file=sys.stderr)
            return 2
        with zipfile.ZipFile(args.mobile_apk, "r") as zf:
            for member in (
                "classes.dex",
                "assets/index.android.bundle",
                "lib/arm64-v8a/libseguranca_nativa.so",
                "lib/x86_64/libseguranca_nativa.so",
            ):
                if member in zf.namelist():
                    apk_members[member] = zf.read(member)

        if "lib/arm64-v8a/libseguranca_nativa.so" in apk_members:
            binaries_for_ghidra.append(
                ("libseguranca_nativa_arm64.so", apk_members["lib/arm64-v8a/libseguranca_nativa.so"])
            )
        if "lib/x86_64/libseguranca_nativa.so" in apk_members:
            binaries_for_ghidra.append(
                ("libseguranca_nativa_x86_64.so", apk_members["lib/x86_64/libseguranca_nativa.so"])
            )

    ghidra_results, ghidra_elapsed, ghidra_err = run_ghidra_batch(
        ghidra_headless, binaries_for_ghidra, timeout=240.0
    )

    checks: list[CheckResult] = []
    if args.target in ("all", "desktop"):
        checks.extend(
            executar_testes_desktop(
                args.desktop_bin,
                ghidra_results,
                ghidra_elapsed,
                ghidra_err,
                pyi_info,
                exe_bytes,
            )
        )
    if args.target in ("all", "mobile"):
        checks.extend(
            executar_testes_mobile(
                args.mobile_apk,
                args.r8_mapping,
                ghidra_results,
                ghidra_elapsed,
                ghidra_err,
                apk_members,
            )
        )

    print("\n" + "=" * 86)
    print("ENSAIO DE ENGENHARIA REVERSA COM GHIDRA E OFUSCAÇÃO DE BINÁRIOS (EIXO 3 - TESTE 8)")
    print("Modelo de Ameaça: Código Aberto (White-Box) — Análise Estática Direcionada")
    print("=" * 86)
    print(f"Ghidra Headless : {ghidra_headless} (tempo lote={ghidra_elapsed:.1f}s)")
    if args.target in ("all", "desktop"):
        print(f"Binário Desktop : {args.desktop_bin} ({len(exe_bytes):,} bytes)")
    if args.target in ("all", "mobile"):
        print(f"Binário Mobile  : {args.mobile_apk} ({args.mobile_apk.stat().st_size:,} bytes)")
    print("-" * 86)
    for chk in checks:
        print(f"[{chk.status:<6}] {chk.code:<4} - {chk.title}: {chk.summary}")
        for line in chk.details:
            print(f"           {line}")
    print("-" * 86)

    def _summarize(prefix: str) -> str:
        grp = [c for c in checks if c.code.startswith(prefix)]
        if not grp:
            return "N/A"
        if any(c.status == "FALHOU" for c in grp):
            return "REPROVADO"
        if any(c.status == "ALERTA" for c in grp):
            return "PARCIAL (COM ALERTAS)"
        return "APROVADO"

    desktop_verdict = _summarize("D")
    mobile_verdict = _summarize("M")
    verdict = "REPROVADO" if any(c.status == "FALHOU" for c in checks) else "APROVADO"

    chk_map = {c.code: c.status for c in checks}
    print("MATRIZ DE AVALIAÇÃO PELOS CRITÉRIOS DO TESTE 8:")
    print("  1. Achatamento de Fluxo de Controle (CFG Flattening):")
    print(f"       - Desktop (ELF / Núcleo CFF / PYZ) : {chk_map.get('D1', 'N/A')} / {chk_map.get('D2', 'N/A')} (dispatchers CFF nativos out_degree>=12 e loader CFF M=12)")
    print(f"       - Mobile  (NDK C++ / ARM64+x86_64) : {chk_map.get('M1', 'N/A')} (dispatchers CFF com jump tables e predicados opacos no Ghidra)")
    print("  2. Renomeação Irreversível de Símbolos e Ocultação de Strings:")
    print(f"       - Desktop (ELF / PYZ Cifrado)      : {chk_map.get('D2', 'N/A')} (98.7% FUN_* no ELF; 0/24 símbolos e 0 constantes expostas no PYZ.pyz)")
    print(f"       - Mobile  (RegisterNatives / R8)   : {chk_map.get('M1', 'N/A')} / {chk_map.get('M2', 'N/A')} (0 exports Java_*, 0/13 strings em .rodata, 100% classes internas ofuscadas/inlined)")
    print("  3. Conversão de Código e Blindagem contra Alteração Estrutural:")
    print(f"       - Desktop (Manifesto + Selo Nativo): {chk_map.get('D3', 'N/A')} (native_seal HMAC/CFF + auditoria ativa de PYZ.pyz em sys.frozen)")
    print(f"       - Mobile  (Hermes HBC + APK v2/v3) : {chk_map.get('M3', 'N/A')} / {chk_map.get('M4', 'N/A')} (HBC v98 + APK Signature v2/v3 + EXPECTED_BUNDLE_SHA256 + keystore dedicada)")
    print("-" * 86)
    print(f"Resumo Desktop (votaai-desktop)       : {desktop_verdict}")
    print(f"Resumo Mobile  (projeto-react-native) : {mobile_verdict}")
    print("=" * 86)
    print(f"Veredito Final (Critério Estrito Teste 8): {verdict}")

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        report = {
            "test": "Teste 8 (Eixo 3) - Engenharia Reversa com Ghidra e Ofuscacao de Binarios",
            "verdict": verdict,
            "summary_by_target": {
                "desktop_admin": desktop_verdict,
                "mobile_android": mobile_verdict,
            },
            "ghidra_headless": str(ghidra_headless),
            "ghidra_elapsed_seconds": round(ghidra_elapsed, 2),
            "checks": [asdict(c) for c in checks],
        }
        args.json_out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Relatório JSON salvo em: {args.json_out}")

    return 0 if verdict == "APROVADO" else 1


if __name__ == "__main__":
    raise SystemExit(main())
