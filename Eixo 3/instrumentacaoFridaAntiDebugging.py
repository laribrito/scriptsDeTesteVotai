"""
Teste 7 (Eixo 3): Instrumentação Dinâmica com Frida e Anti-Debugging

Verifica a capacidade das aplicações clientes (votaai-desktop e projeto-react-native)
de detectar modificações no ambiente de execução, anexação de depuradores e
adulteração/ganchos de código em tempo real utilizando EXCLUSIVAMENTE as instalações
e binários originais (sem recompilação nem modificação de APKs).

Alvos e cenários avaliados:
  1. Módulo Administrativo (votaai-desktop — binário dist/votaai-desktop):
       - D0: Controle positivo e hardening de kernel (PR_SET_DUMPABLE=0, PR_SET_NO_NEW_PRIVS=1).
       - D1: Tentativa de anexo direto do GDB e Frida ao binário em execução.
       - D2: Execução direta do binário sob GDB (TracerPid != 0 / processo pai gdb).
       - D3: Vetores adicionais contra o binário (strace, LD_PRELOAD, -qmljsdebugger, SUDO_USER).
       - D4: Watchdog contínuo em runtime (sys.settrace e monkey-patching em memória).
       - D5: Auditoria de contorno via variável de ambiente (VOTAAI_SECURITY_GUARD=0).
  2. Aplicativo Móvel — Smartphone Físico SEM Root (instalação original intacta):
       - M-FIS-1: Integridade do pacote release instalado e bloqueio nativo OS de run-as / JDWP.
       - M-FIS-2: Sonda da porta padrão do Frida (127.0.0.1:27042) via adb reverse (não destrutivo).
  3. Aplicativo Móvel — Emulador Android COM Root (app-release.apk 100% original + adb root):
       - M-EMU-1: Detecção de ambiente rooteado, artefatos de Magisk e emulador.
       - M-EMU-2: Anexo de depurador nativo real (lldb-server / ptrace -> TracerPid != 0) em execução contínua.
       - M-EMU-3: Instrumentação dinâmica com frida-server real (detecção nativa e tentativa
                  de sobreposição dos métodos de verificação de integridade).

Critério de validação:
  O teste é aprovado se as aplicações encerrarem imediatamente sua própria execução ao
  detectar o ambiente modificado, presença de binários do Magisk, ganchos dinâmicos ou
  anexação de depuradores, impedindo a manipulação de fluxo e a leitura de variáveis
  de memória que contenham dados confidenciais do voto ou do eleitor.
"""

from __future__ import annotations

import argparse
import ctypes.util
import glob
import json
import os
import pathlib
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

# ==============================================================================
# Constantes e Caminhos Padrão
# ==============================================================================
REPO_ROOT = Path(__file__).resolve().parent.parent
DESKTOP_DIR = Path("/home/debrito/Programação/votaai-desktop")
DEFAULT_DESKTOP_BIN = DESKTOP_DIR / "dist" / "votaai-desktop"
DESKTOP_VENV_PYTHON = DESKTOP_DIR / ".venv" / "bin" / "python"

MOBILE_DIR = Path("/home/debrito/Programação/projeto-react-native")
DEFAULT_MOBILE_APK = MOBILE_DIR / "android" / "app" / "build" / "outputs" / "apk" / "release" / "app-release.apk"
MOBILE_PACKAGE = "com.meuapptestecripto"
MOBILE_MAIN_ACTIVITY = f"{MOBILE_PACKAGE}/.MainActivity"

DEFAULT_ADB = Path.home() / "Android" / "Sdk" / "platform-tools" / "adb"
DEFAULT_EMULATOR_BIN = Path.home() / "Android" / "Sdk" / "emulator" / "emulator"
DEFAULT_AVD_NAME = "votaai_root_api34"
DEFAULT_FRIDA_SERVER = REPO_ROOT / ".venv" / "share" / "frida" / "frida-server-android-x86_64"


@dataclass
class CheckResult:
    code: str
    title: str
    status: str  # "PASSOU" | "FALHOU" | "ALERTA" | "N/A"
    summary: str
    details: list[str] = field(default_factory=list)


# ==============================================================================
# Utilitários Gerais, ADB e Processos Linux
# ==============================================================================
def run_cmd(
    cmd: list[str],
    env: dict[str, str] | None = None,
    cwd: Path | None = None,
    timeout: float = 30.0,
) -> tuple[int, str, str, float, bool]:
    """Executa comando com timeout e retorna (rc, stdout, stderr, elapsed_s, timed_out)."""
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


def find_adb(explicit: Path | None = None) -> str:
    if explicit and explicit.is_file():
        return str(explicit)
    if DEFAULT_ADB.is_file():
        return str(DEFAULT_ADB)
    return shutil.which("adb") or "adb"


def find_lldb_server(explicit: Path | None = None) -> Path | None:
    if explicit and explicit.is_file():
        return explicit
    pattern = str(
        Path.home()
        / "Android"
        / "Sdk"
        / "ndk"
        / "*"
        / "toolchains"
        / "llvm"
        / "prebuilt"
        / "linux-x86_64"
        / "lib"
        / "clang"
        / "*"
        / "lib"
        / "linux"
        / "x86_64"
        / "lldb-server"
    )
    matches = sorted(glob.glob(pattern))
    return Path(matches[-1]) if matches else None


def find_lldb_client() -> Path | None:
    pattern = str(
        Path.home()
        / "Android"
        / "Sdk"
        / "ndk"
        / "*"
        / "toolchains"
        / "llvm"
        / "prebuilt"
        / "linux-x86_64"
        / "bin"
        / "lldb.sh"
    )
    matches = sorted(glob.glob(pattern))
    return Path(matches[-1]) if matches else None


def adb_run(adb_bin: str, serial: str, *args: str, timeout: float = 20.0) -> tuple[int, str, str, bool]:
    rc, out, err, _, timed_out = run_cmd([adb_bin, "-s", serial, *args], timeout=timeout)
    return rc, out, err, timed_out


def list_adb_devices(adb_bin: str) -> tuple[list[str], list[str]]:
    """Retorna (physical_serials, emulator_serials) em estado 'device'."""
    rc, out, _, _, _ = run_cmd([adb_bin, "devices"], timeout=10.0)
    if rc != 0:
        return [], []
    physical: list[str] = []
    emulators: list[str] = []
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("List of devices"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            serial = parts[0]
            if serial.startswith("emulator-"):
                emulators.append(serial)
            else:
                physical.append(serial)
    return physical, emulators


def read_proc_status(pid: int) -> dict[str, str]:
    info: dict[str, str] = {}
    try:
        text = Path(f"/proc/{pid}/status").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return info
    for line in text.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            info[k.strip()] = v.strip()
    return info


def find_child_pids(parent_pid: int) -> list[int]:
    children: list[int] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        st = read_proc_status(pid)
        if st.get("PPid") == str(parent_pid):
            children.append(pid)
    return sorted(children)


def snapshot_mei_dirs() -> set[str]:
    return {p.name for p in Path("/tmp").glob("_MEI*") if p.is_dir()}


def cleanup_new_mei_dirs(before_dirs: set[str]) -> None:
    """Remove apenas diretórios /tmp/_MEI* criados pelo próprio teste caso o bootloader não limpe."""
    active_dirs: set[str] = set()
    for p in Path("/proc").iterdir():
        if not p.name.isdigit():
            continue
        try:
            maps_txt = (p / "maps").read_text(encoding="utf-8", errors="replace")
            for m in re.findall(r"/tmp/(_MEI[^/\s]+)", maps_txt):
                active_dirs.add(m)
        except OSError:
            pass
    for d in Path("/tmp").glob("_MEI*"):
        if d.is_dir() and d.name not in before_dirs and d.name not in active_dirs:
            shutil.rmtree(d, ignore_errors=True)


def launch_desktop_and_wait_child(
    desktop_bin: Path,
    extra_env: dict[str, str] | None = None,
    extra_args: list[str] | None = None,
    startup_timeout: float = 75.0,
    require_hardening: bool = True,
) -> tuple[subprocess.Popen[str], int | None, bool, str, str, float, set[str]]:
    """
    Sobe o executável PyInstaller headless e aguarda o filho Python inicializar (ou entrar no runtime).
    Retorna (proc, child_pid, exited_early, stdout, stderr, elapsed_s, mei_before).
    """
    mei_before = snapshot_mei_dirs()
    env = os.environ.copy()
    env["QT_QPA_PLATFORM"] = "offscreen"
    if extra_env:
        env.update(extra_env)

    t0 = time.monotonic()
    proc = subprocess.Popen(
        [str(desktop_bin), *(extra_args or [])],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
    )

    child_pid: int | None = None
    first_seen_child_at: float | None = None
    while time.monotonic() - t0 < startup_timeout:
        if proc.poll() is not None:
            out, err = proc.communicate(timeout=3)
            return proc, child_pid, True, out, err, time.monotonic() - t0, mei_before

        children = find_child_pids(proc.pid)
        for cpid in children:
            child_pid = cpid
            if first_seen_child_at is None:
                first_seen_child_at = time.monotonic()
            st = read_proc_status(cpid)
            if st.get("NoNewPrivs") == "1":
                time.sleep(0.5)
                if proc.poll() is not None:
                    out, err = proc.communicate(timeout=3)
                    return proc, cpid, True, out, err, time.monotonic() - t0, mei_before
                return proc, cpid, False, "", "", time.monotonic() - t0, mei_before
            if (not require_hardening) and (time.monotonic() - first_seen_child_at >= 2.0):
                return proc, cpid, False, "", "", time.monotonic() - t0, mei_before
        time.sleep(0.25)

    return proc, child_pid, proc.poll() is not None, "", "", time.monotonic() - t0, mei_before


def terminate_desktop_tree(
    proc: subprocess.Popen[str],
    child_pid: int | None,
    mei_before: set[str],
) -> tuple[str, str]:
    """Encerra processo pai e filho PyInstaller de forma limpa, removendo _MEI residual do ensaio."""
    out = ""
    err = ""
    try:
        if proc.poll() is None:
            proc.terminate()
            try:
                out, err = proc.communicate(timeout=8)
            except subprocess.TimeoutExpired:
                for cpid in set(([child_pid] if child_pid else []) + find_child_pids(proc.pid)):
                    try:
                        os.kill(cpid, 9)
                    except OSError:
                        pass
                proc.kill()
                out, err = proc.communicate(timeout=3)
        else:
            out, err = proc.communicate(timeout=3)
    except Exception:
        pass
    cleanup_new_mei_dirs(mei_before)
    return out, err


def find_free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def adb_get_pid(adb_bin: str, serial: str, package: str = MOBILE_PACKAGE) -> list[int]:
    _, out, _, _ = adb_run(adb_bin, serial, "shell", "pidof", package, timeout=10.0)
    pids: list[int] = []
    for tok in out.strip().split():
        if tok.isdigit():
            pids.append(int(tok))
    return pids


def adb_dump_ui(adb_bin: str, serial: str) -> tuple[str, list[str], dict[str, tuple[int, int]]]:
    """Captura uiautomator dump via arquivo temporário no dispositivo e retorna (xml_raw, textos_visiveis, mapa_texto_para_centro)."""
    xml_raw = ""
    xml_clean = ""
    candidates = ("/sdcard/votaai_window_dump.xml", "/data/local/tmp/votaai_window_dump.xml")
    for attempt in range(3):
        dump_path = candidates[attempt % len(candidates)]
        _, out, _, _ = adb_run(
            adb_bin,
            serial,
            "shell",
            f"uiautomator dump --compressed {dump_path} >/dev/null 2>&1 && cat {dump_path}; rm -f {dump_path}",
            timeout=15.0,
        )
        xml_raw = out
        start = out.find("<hierarchy")
        end = out.rfind("</hierarchy>")
        if start != -1 and end != -1:
            xml_clean = out[start : end + len("</hierarchy>")]
            break
        time.sleep(1.0)
    if not xml_clean:
        return xml_raw, [], {}

    texts: list[str] = []
    centers: dict[str, tuple[int, int]] = {}
    try:
        root = ET.fromstring(xml_clean)
        for node in root.iter("node"):
            txt = (node.attrib.get("text") or "").strip()
            desc = (node.attrib.get("content-desc") or "").strip()
            label = txt or desc
            if label:
                texts.append(label)
                bounds = node.attrib.get("bounds", "")
                m = re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", bounds)
                if m:
                    x1, y1, x2, y2 = map(int, m.groups())
                    centers[label] = ((x1 + x2) // 2, (y1 + y2) // 2)
    except ET.ParseError:
        pass
    return xml_clean, texts, centers


def adb_open_vote_link_and_confirm(
    adb_bin: str,
    serial: str,
    token: str,
    user_zero: bool = False,
) -> tuple[list[str], bool]:
    """
    Abre deep link sintético no app e toca em 'Abrir eleição' se a tela de confirmação aparecer.
    Retorna (textos_ui_finais, clicou_confirmar).
    """
    user_args = ["--user", "0"] if user_zero else []
    adb_run(
        adb_bin,
        serial,
        "shell",
        "am",
        "start",
        *user_args,
        "-a",
        "android.intent.action.VIEW",
        "-d",
        f"votaai://votar/?token={token}",
        MOBILE_PACKAGE,
        timeout=15.0,
    )
    texts: list[str] = []
    centers: dict[str, tuple[int, int]] = {}
    btn_candidates: list[tuple[str, tuple[int, int]]] = []
    for _ in range(4):
        time.sleep(1.5)
        if not adb_get_pid(adb_bin, serial):
            return [], False
        _, texts, centers = adb_dump_ui(adb_bin, serial)
        btn_candidates = [
            (label, coords)
            for label, coords in centers.items()
            if (label.strip().lower() == "abrir eleição")
            or ("abrir elei" in label.strip().lower() and "?" not in label)
        ]
        if btn_candidates:
            break

    clicked = False
    if btn_candidates:
        _, (cx, cy) = max(btn_candidates, key=lambda item: item[1][1])
        adb_run(adb_bin, serial, "shell", "input", "tap", str(cx), str(cy), timeout=10.0)
        clicked = True
        for _ in range(2):
            time.sleep(2.0)
            _, texts, _ = adb_dump_ui(adb_bin, serial)
            if texts:
                break
    return texts, clicked


# ==============================================================================
# Bloco A — Módulo Administrativo (votaai-desktop)
# ==============================================================================
def executar_testes_desktop(desktop_bin: Path, desktop_py: Path) -> list[CheckResult]:
    results: list[CheckResult] = []
    if not desktop_bin.is_file():
        return [
            CheckResult(
                "D0",
                "Desktop | Binário votaai-desktop",
                "FALHOU",
                f"Binário não encontrado em '{desktop_bin}'.",
            )
        ]

    gdb_bin = shutil.which("gdb")
    strace_bin = shutil.which("strace")

    # ------------------------------------------------------------------
    # D0: Controle Positivo + Hardening de Kernel (PR_SET_DUMPABLE=0)
    # ------------------------------------------------------------------
    proc, child_pid, exited_early, out, err, elapsed, mei_before = launch_desktop_and_wait_child(desktop_bin)
    try:
        if exited_early or child_pid is None:
            results.append(
                CheckResult(
                    "D0",
                    "Desktop | Controle Positivo e Hardening de Kernel (binário original)",
                    "FALHOU",
                    f"Binário falhou ou não inicializou o processo filho protegido em {elapsed:.2f}s (exited={exited_early}).",
                    [f"stdout={out.strip()[:300]}", f"stderr={err.strip()[:300]}"],
                )
            )
            return results

        st = read_proc_status(child_pid)
        tracer_pid = st.get("TracerPid", "?")
        no_new_privs = st.get("NoNewPrivs", "?")

        mem_blocked = False
        mem_msg = ""
        try:
            with open(f"/proc/{child_pid}/mem", "rb") as f:
                f.read(16)
            mem_msg = "LEITURA PERMITIDA (FALHA)"
        except PermissionError as exc:
            mem_blocked = True
            mem_msg = f"PermissionError ({exc})"
        except OSError as exc:
            mem_blocked = True
            mem_msg = f"OSError ({exc})"

        maps_blocked = False
        maps_msg = ""
        try:
            Path(f"/proc/{child_pid}/maps").read_text(encoding="utf-8")
            maps_msg = "LEITURA PERMITIDA"
        except PermissionError as exc:
            maps_blocked = True
            maps_msg = f"PermissionError ({exc})"
        except OSError as exc:
            maps_blocked = True
            maps_msg = f"OSError ({exc})"

        time.sleep(3.0)
        stayed_alive = proc.poll() is None and Path(f"/proc/{child_pid}").exists()
        d0_ok = stayed_alive and tracer_pid == "0" and no_new_privs == "1" and mem_blocked

        results.append(
            CheckResult(
                "D0",
                "Desktop | Controle Positivo e Hardening de Kernel (binário original)",
                "PASSOU" if d0_ok else "FALHOU",
                (
                    f"Binário original inicializou em {elapsed:.2f}s (PID pai={proc.pid}, filho={child_pid}), "
                    f"manteve-se estável por 3s com NoNewPrivs=1 e bloqueou leitura direta de /proc/<pid>/mem."
                    if d0_ok
                    else "Falha no controle positivo ou nas travas de kernel do processo Desktop."
                ),
                [
                    f"child_pid={child_pid} (PPid={st.get('PPid')}) | TracerPid={tracer_pid} | NoNewPrivs={no_new_privs}",
                    f"Leitura /proc/{child_pid}/mem (PR_SET_DUMPABLE=0): {mem_msg}",
                    f"Leitura /proc/{child_pid}/maps: {maps_msg}",
                    f"Estabilidade após 3,0s sem depurador: vivo={stayed_alive}",
                ],
            )
        )

        # ------------------------------------------------------------------
        # D1: Tentativa de Anexo Direto com GDB e Frida ao Processo Vivo
        # ------------------------------------------------------------------
        d1_details: list[str] = []
        gdb_blocked = False
        if gdb_bin:
            g_rc, g_out, g_err, g_dt, g_to = run_cmd(
                [
                    gdb_bin,
                    "-batch",
                    "-ex",
                    f"attach {child_pid}",
                    "-ex",
                    "info registers",
                    "-ex",
                    "bt 3",
                    "-ex",
                    "detach",
                    "-ex",
                    "quit",
                ],
                timeout=15.0,
            )
            g_combined = (g_out + "\n" + g_err).strip()
            has_perm_denied = any(
                k in g_combined.lower()
                for k in ("operation not permitted", "ptrace", "could not attach", "not permitted")
            )
            leaked_regs = ("rip " in g_combined.lower() or "rax " in g_combined.lower()) and not has_perm_denied
            child_dead = not Path(f"/proc/{child_pid}").exists()
            gdb_blocked = (not leaked_regs) and (has_perm_denied or g_rc != 0 or child_dead)
            d1_details.append(
                f"GDB attach PID {child_pid}: rc={g_rc}, tempo={g_dt:.2f}s, timeout={g_to}, "
                f"bloqueado={gdb_blocked} | saída='{' | '.join(g_combined.splitlines()[:4])}'"
            )
        else:
            d1_details.append("GDB não encontrado no PATH.")

        frida_blocked = True
        try:
            import frida  # type: ignore

            try:
                sess = frida.attach(child_pid)
                sess.detach()
                frida_blocked = False
                d1_details.append(f"Frida attach local PID {child_pid}: ANEXOU SEM BLOQUEIO (VULNERÁVEL)")
            except Exception as exc:
                frida_blocked = True
                d1_details.append(
                    f"Frida attach local PID {child_pid}: bloqueado ({type(exc).__name__}: {exc})"
                )
        except ImportError:
            d1_details.append("Módulo Python 'frida' indisponível neste interpretador (checagem de Frida local pulada).")

        d1_ok = bool(gdb_bin) and gdb_blocked and frida_blocked
        results.append(
            CheckResult(
                "D1",
                "Desktop | Anexo Direto de GDB e Frida ao Executável em Execução",
                "PASSOU" if d1_ok else "FALHOU",
                (
                    "Kernel/SecurityGuard impediu anexação do GDB (ptrace negado via PR_SET_DUMPABLE=0) e do Frida local sem vazar registradores ou memória."
                    if d1_ok
                    else "Depurador ou instrumentador conseguiu anexar ou ler contexto do processo em execução."
                ),
                d1_details,
            )
        )
    finally:
        terminate_desktop_tree(proc, child_pid, mei_before)

    # ------------------------------------------------------------------
    # D2: Execução Direta do Binário Sob GDB (TracerPid != 0 + pai gdb)
    # ------------------------------------------------------------------
    if gdb_bin:
        mei_before_d2 = snapshot_mei_dirs()
        env_d2 = os.environ.copy()
        env_d2["QT_QPA_PLATFORM"] = "offscreen"
        g_rc, g_out, g_err, g_dt, g_to = run_cmd(
            [
                gdb_bin,
                "-batch",
                "-ex",
                "set pagination off",
                "-ex",
                "set follow-fork-mode child",
                "-ex",
                "run",
                "-ex",
                "quit",
                "--args",
                str(desktop_bin),
            ],
            env=env_d2,
            timeout=75.0,
        )
        cleanup_new_mei_dirs(mei_before_d2)
        g_all = g_out + "\n" + g_err
        detected_msg = "VIOLAÇÃO CRÍTICA DETECTADA" in g_all and "Anti-Debug" in g_all
        exited_nonzero = "exited with code 01" in g_all or "exited with code 1" in g_all
        d2_ok = (not g_to) and detected_msg and exited_nonzero
        relevant = [ln.strip() for ln in g_all.splitlines() if any(w in ln for w in ("SecurityGuard", "TracerPid", "exited", "process", "Anti-Debug"))]
        results.append(
            CheckResult(
                "D2",
                "Desktop | Execução Sob GDB (detecção ativa de TracerPid / pai gdb)",
                "PASSOU" if d2_ok else "FALHOU",
                (
                    f"Processo abortou imediatamente via os._exit(1) em {g_dt:.2f}s ao detectar depurador anexado sob GDB."
                    if d2_ok
                    else f"Processo não confirmou autoencerramento esperado sob GDB (rc={g_rc}, timeout={g_to})."
                ),
                relevant[:8] or [g_all.strip()[:400]],
            )
        )
    else:
        results.append(CheckResult("D2", "Desktop | Execução Sob GDB", "N/A", "GDB não instalado."))

    # ------------------------------------------------------------------
    # D3: Vetores Adicionais (strace, LD_PRELOAD, -qmljsdebugger, SUDO_USER)
    # ------------------------------------------------------------------
    libc_path = ctypes.util.find_library("c") or "/lib/x86_64-linux-gnu/libc.so.6"
    if not Path(libc_path).exists():
        libc_path = "/lib/x86_64-linux-gnu/libc.so.6"

    vectors: list[tuple[str, list[str], dict[str, str], str]] = []
    if strace_bin:
        vectors.append(
            (
                "strace",
                [strace_bin, "-f", "-e", "trace=execve", "-o", "/dev/null", str(desktop_bin)],
                {},
                "Anti-Debug",
            )
        )
    vectors.extend(
        [
            ("LD_PRELOAD", [str(desktop_bin)], {"LD_PRELOAD": libc_path}, "Anti-Tamper"),
            ("-qmljsdebugger", [str(desktop_bin), "-qmljsdebugger=port:3768"], {}, ""),
            ("SUDO_USER", [str(desktop_bin)], {"SUDO_USER": "root"}, "Anti-Root"),
        ]
    )

    d3_details: list[str] = []
    d3_all_ok = True
    for label, cmd, extra_env, expected_tag in vectors:
        mei_b = snapshot_mei_dirs()
        env_v = os.environ.copy()
        env_v["QT_QPA_PLATFORM"] = "offscreen"
        env_v.update(extra_env)
        v_rc, v_out, v_err, v_dt, v_to = run_cmd(cmd, env=env_v, timeout=75.0)
        cleanup_new_mei_dirs(mei_b)
        combined = (v_out + "\n" + v_err).strip()
        tag_ok = (expected_tag in combined) if expected_tag else True
        # -qmljsdebugger encerra no harden_process_memory() silenciosamente com os._exit(1)
        vec_ok = (not v_to) and (v_rc != 0) and tag_ok
        if not vec_ok:
            d3_all_ok = False
        first_line = next((ln.strip() for ln in combined.splitlines() if "SecurityGuard" in ln), combined[:160])
        d3_details.append(f"{label}: rc={v_rc}, dt={v_dt:.2f}s, timeout={v_to}, bloqueado={vec_ok} | '{first_line}'")

    results.append(
        CheckResult(
            "D3",
            "Desktop | Vetores Adicionais (strace, LD_PRELOAD, -qmljsdebugger, SUDO_USER)",
            "PASSOU" if d3_all_ok else "FALHOU",
            (
                f"Todos os {len(vectors)} vetores de instrumentação/privilégio foram imediatamente abortados pelo SecurityGuard."
                if d3_all_ok
                else "Um ou mais vetores adicionais não causaram aborto imediato esperado."
            ),
            d3_details,
        )
    )

    # ------------------------------------------------------------------
    # D4: Watchdog Contínuo (sys.settrace e Monkey-Patching em Memória)
    # ------------------------------------------------------------------
    if desktop_py.is_file():
        d4_cases = [
            (
                "sys.settrace",
                (
                    "import sys, time; "
                    "from app.services.security_guard import SecurityGuard; "
                    "SecurityGuard.initialize(start_watchdog=True, interval_seconds=0.3); "
                    "time.sleep(0.4); "
                    "sys.settrace(lambda f, e, a: None); "
                    "time.sleep(3.0)"
                ),
            ),
            (
                "monkey_patch_decrypt_vote",
                (
                    "import time; "
                    "from app.services.security_guard import SecurityGuard; "
                    "from app.controllers.cryptoController import CryptoController; "
                    "SecurityGuard.initialize(start_watchdog=True, interval_seconds=0.3); "
                    "time.sleep(0.4); "
                    "CryptoController.decrypt_vote = staticmethod(lambda *a, **kw: b'FORGED'); "
                    "time.sleep(3.0)"
                ),
            ),
        ]
        d4_details: list[str] = []
        d4_ok = True
        for name, code in d4_cases:
            rc, out, err, dt, to = run_cmd([str(desktop_py), "-c", code], cwd=DESKTOP_DIR, timeout=15.0)
            msg = (out + "\n" + err).strip().splitlines()
            last_msg = msg[-1] if msg else ""
            case_ok = (not to) and (rc != 0) and ("VIOLAÇÃO CRÍTICA DETECTADA" in (out + err))
            if not case_ok:
                d4_ok = False
            d4_details.append(f"{name}: rc={rc}, dt={dt:.2f}s, timeout={to}, abortou={case_ok} | '{last_msg}'")
        if not d4_ok:
            d4_details.append(
                "Nota técnica: em CPython sys.gettrace() é thread-local; quando sys.settrace() é instalado na MainThread, "
                "o VotaAISecurityWatchdog (em thread daemon separada) observa sys.gettrace() == None."
            )

        results.append(
            CheckResult(
                "D4",
                "Desktop | Watchdog Contínuo em Runtime (sys.settrace e Monkey-Patching)",
                "PASSOU" if d4_ok else "FALHOU",
                (
                    "Watchdog em background detectou injeção de tracer Python e adulteração de bytecode/método em memória, encerrando via os._exit(1)."
                    if d4_ok
                    else "Watchdog detectou e abortou monkey-patching de CryptoController.decrypt_vote, mas não detectou sys.settrace() na MainThread (sys.gettrace() é thread-local)."
                ),
                d4_details,
            )
        )
    else:
        results.append(CheckResult("D4", "Desktop | Watchdog Contínuo", "N/A", f"Venv não encontrado em {desktop_py}."))

    # ------------------------------------------------------------------
    # D5: Auditoria de Contorno via Variável de Ambiente VOTAAI_SECURITY_GUARD=0
    # ------------------------------------------------------------------
    proc5, cpid5, early5, out5, err5, dt5, mei5 = launch_desktop_and_wait_child(
        desktop_bin,
        extra_env={"VOTAAI_SECURITY_GUARD": "0", "SUDO_USER": "root", "LD_PRELOAD": libc_path},
        startup_timeout=75.0,
        require_hardening=False,
    )
    try:
        # Se SecurityGuard foi desabilitado, o processo filho sobe com NoNewPrivs=0
        time.sleep(2.5)
        alive5 = proc5.poll() is None
        childs5 = find_child_pids(proc5.pid) if alive5 else []
        nnp5 = read_proc_status(childs5[0]).get("NoNewPrivs") if childs5 else None
        bypassed = alive5 and (not early5) and (nnp5 == "0")
        results.append(
            CheckResult(
                "D5",
                "Desktop | Auditoria de Kill-Switch por Ambiente (VOTAAI_SECURITY_GUARD=0)",
                "ALERTA" if bypassed else "PASSOU",
                (
                    "Kill-switch VOTAAI_SECURITY_GUARD=0 permanece ativo no binário compilado, permitindo iniciar sob SUDO_USER+LD_PRELOAD sem hardening."
                    if bypassed
                    else "Binário bloqueou execução mesmo com VOTAAI_SECURITY_GUARD=0."
                ),
                [
                    f"alive={alive5}, early_exit={early5}, child_pids={childs5}, NoNewPrivs={nnp5}",
                    "Recomendação: desabilitar ou ignorar VOTAAI_SECURITY_GUARD=0 em builds PyInstaller de produção (sys.frozen).",
                ],
            )
        )
    finally:
        terminate_desktop_tree(proc5, cpid5 or (find_child_pids(proc5.pid)[0] if find_child_pids(proc5.pid) else None), mei5)

    return results


# ==============================================================================
# Bloco B — Mobile no Smartphone Físico SEM Root (Instalação Original)
# ==============================================================================
def executar_testes_mobile_fisico(adb_bin: str, serial: str) -> list[CheckResult]:
    results: list[CheckResult] = []
    _, model_out, _, _ = adb_run(adb_bin, serial, "shell", "getprop", "ro.product.model", timeout=10.0)
    _, rel_out, _, _ = adb_run(adb_bin, serial, "shell", "getprop", "ro.build.version.release", timeout=10.0)
    model = model_out.strip() or serial
    android_rel = rel_out.strip() or "?"

    # ------------------------------------------------------------------
    # M-FIS-1: Integridade da Instalação Original e Bloqueio OS (run-as/JDWP)
    # ------------------------------------------------------------------
    rc_pm, pm_out, pm_err, _ = adb_run(adb_bin, serial, "shell", "pm", "path", "--user", "0", MOBILE_PACKAGE)
    if rc_pm != 0 or "package:" not in pm_out:
        return [
            CheckResult(
                "M-FIS-1",
                f"Mobile Físico ({model}) | Instalação Original",
                "FALHOU",
                f"Pacote original {MOBILE_PACKAGE} não está instalado no usuário 0 de {serial}.",
                [pm_out.strip(), pm_err.strip()],
            )
        ]

    _, dump_out, _, _ = adb_run(adb_bin, serial, "shell", "dumpsys", "package", MOBILE_PACKAGE)
    flags_line = next((ln.strip() for ln in dump_out.splitlines() if "flags=[" in ln and "pkgFlags=" not in ln), "")
    is_debuggable = "DEBUGGABLE" in flags_line

    rc_runas, runas_out, runas_err, _ = adb_run(adb_bin, serial, "shell", "run-as", MOBILE_PACKAGE, "id")
    runas_blocked = rc_runas != 0 or "not debuggable" in (runas_out + runas_err).lower()

    adb_run(adb_bin, serial, "shell", "am", "force-stop", "--user", "0", MOBILE_PACKAGE)
    adb_run(adb_bin, serial, "shell", "am", "start", "--user", "0", "-W", "-n", MOBILE_MAIN_ACTIVITY, timeout=20.0)
    time.sleep(3.5)
    pids = adb_get_pid(adb_bin, serial)

    # adb jdwp é streaming; timeout curto de 1.5s para capturar lista atual de PIDs JDWP
    _, jdwp_out, _, _, _ = run_cmd([adb_bin, "-s", serial, "jdwp"], timeout=1.5)
    jdwp_pids = {ln.strip() for ln in jdwp_out.splitlines() if ln.strip().isdigit()}
    pid_in_jdwp = any(str(p) in jdwp_pids for p in pids)

    m1_ok = (not is_debuggable) and runas_blocked and bool(pids) and (not pid_in_jdwp)
    results.append(
        CheckResult(
            "M-FIS-1",
            f"Mobile Físico ({model}, Android {android_rel}) | Build Release Original e Bloqueio run-as/JDWP",
            "PASSOU" if m1_ok else "FALHOU",
            (
                "Instalação release original confirmada (não depurável), run-as/JDWP bloqueados pelo SO e controle positivo ativo."
                if m1_ok
                else "Falha na verificação de build release não depurável ou controle positivo."
            ),
            [
                f"APK path: {pm_out.strip()}",
                f"Package flags: {flags_line or 'N/A'} (debuggable={is_debuggable})",
                f"run-as {MOBILE_PACKAGE}: bloqueado={runas_blocked} ({(runas_out + runas_err).strip()})",
                f"Controle positivo em aparelho físico limpo: PIDs={pids} | exposto em JDWP={pid_in_jdwp}",
            ],
        )
    )

    # ------------------------------------------------------------------
    # M-FIS-2: Sonda da Porta Frida (127.0.0.1:27042) via adb reverse
    # ------------------------------------------------------------------
    stop_evt = threading.Event()
    conn_count = 0
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    srv.settimeout(0.3)
    host_port = int(srv.getsockname()[1])

    def _accept_loop() -> None:
        nonlocal conn_count
        while not stop_evt.is_set():
            try:
                c, _ = srv.accept()
                conn_count += 1
                c.close()
            except socket.timeout:
                continue
            except OSError:
                break

    th = threading.Thread(target=_accept_loop, daemon=True)
    th.start()
    try:
        rc_rev, _, rev_err, _ = adb_run(adb_bin, serial, "reverse", "tcp:27042", f"tcp:{host_port}")
        adb_run(adb_bin, serial, "shell", "am", "force-stop", "--user", "0", MOBILE_PACKAGE)
        time.sleep(0.5)
        ui_texts, clicked_confirm = adb_open_vote_link_and_confirm(
            adb_bin,
            serial,
            "FRIDA_PROBE_27042_PHYSICAL",
            user_zero=True,
        )
        pids_after = adb_get_pid(adb_bin, serial)
        blocked_ui = any(
            "depuração ou instrumentação detectada" in t.lower() or "acesso bloqueado por segurança" in t.lower()
            for t in ui_texts
        )
        process_terminated = len(pids_after) == 0

        if rc_rev != 0:
            status_m2 = "FALHOU"
            summary_m2 = f"Falha ao configurar adb reverse tcp:27042: {rev_err.strip()}"
        elif conn_count > 0 and process_terminated:
            status_m2 = "PASSOU"
            summary_m2 = f"Sonda nativa detectou porta Frida 27042 ({conn_count} conexão(ões)) e encerrou imediatamente a execução."
        elif conn_count > 0 and blocked_ui:
            status_m2 = "ALERTA"
            summary_m2 = (
                f"Sonda nativa conectou na porta 27042 ({conn_count}x) e exibiu tela de bloqueio, "
                f"porém o processo não se autoencerrou (PIDs={pids_after})."
            )
        else:
            status_m2 = "FALHOU"
            summary_m2 = "Porta 27042 não foi detectada nem bloqueou a sessão de votação."

        results.append(
            CheckResult(
                "M-FIS-2",
                f"Mobile Físico ({model}) | Detecção de Porta Frida 27042 (sem root, APK intacto)",
                status_m2,
                summary_m2,
                [
                    f"Conexões TCP recebidas do celular em 127.0.0.1:27042: {conn_count}",
                    f"Deep link confirmado na UI={clicked_confirm} | Tela de bloqueio exibida={blocked_ui}",
                    f"Textos relevantes UI: {[t for t in ui_texts if any(k in t.lower() for k in ('depuração', 'bloqueado', 'segurança', 'vota'))][:6]}",
                    f"Processo encerrado={process_terminated} (PIDs={pids_after}) — nota: MainActivity.onResume checa verificarDepuracaoCritica(), mas detectarPortaFridaSeguro() roda apenas em verificarTudo().",
                ],
            )
        )
    finally:
        stop_evt.set()
        srv.close()
        th.join(timeout=2.0)
        adb_run(adb_bin, serial, "shell", "am", "force-stop", "--user", "0", MOBILE_PACKAGE)
        adb_run(adb_bin, serial, "reverse", "--remove", "tcp:27042")

    return results


# ==============================================================================
# Bloco C — Mobile no Emulador Android COM Root (app-release.apk Original)
# ==============================================================================
def ensure_emulator_ready(
    adb_bin: str,
    emulator_bin: Path,
    avd_name: str,
    requested_serial: str | None,
    auto_start: bool,
    mobile_apk: Path,
) -> tuple[str | None, subprocess.Popen[bytes] | None, str]:
    """Garante emulador rodando com adb root (uid=0) e APK release original instalado."""
    _, emulators = list_adb_devices(adb_bin)
    emu_serial = requested_serial if (requested_serial and requested_serial in emulators) else (emulators[0] if emulators else None)
    started_proc: subprocess.Popen[bytes] | None = None

    if not emu_serial and auto_start:
        if not emulator_bin.is_file():
            return None, None, f"Binário emulator não encontrado em {emulator_bin}."
        started_proc = subprocess.Popen(
            [
                str(emulator_bin),
                "-avd",
                avd_name,
                "-no-window",
                "-no-audio",
                "-no-boot-anim",
                "-no-snapshot-save",
                "-gpu",
                "swiftshader_indirect",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        for _ in range(90):
            _, emulators = list_adb_devices(adb_bin)
            if emulators:
                emu_serial = emulators[0]
                break
            time.sleep(1.0)
        if not emu_serial:
            return None, started_proc, "Timeout aguardando emulador registrar no ADB."
        adb_run(adb_bin, emu_serial, "wait-for-device", timeout=60.0)
        for _ in range(120):
            _, boot, _, _ = adb_run(adb_bin, emu_serial, "shell", "getprop", "sys.boot_completed")
            if boot.strip() == "1":
                break
            time.sleep(1.0)

    if not emu_serial:
        return None, None, "Nenhum emulador ativo encontrado (use --auto-start-emulator ou inicie o AVD)."

    adb_run(adb_bin, emu_serial, "root", timeout=15.0)
    time.sleep(1.5)
    adb_run(adb_bin, emu_serial, "wait-for-device", timeout=20.0)
    _, id_out, _, _ = adb_run(adb_bin, emu_serial, "shell", "id")
    if "uid=0" not in id_out:
        return emu_serial, started_proc, f"Emulador {emu_serial} não concedeu adb root (id='{id_out.strip()}')."

    if not mobile_apk.is_file():
        _, pm_out, _, _ = adb_run(adb_bin, emu_serial, "shell", "pm", "path", MOBILE_PACKAGE)
        if "package:" not in pm_out:
            return emu_serial, started_proc, f"APK original não encontrado em {mobile_apk}."
    else:
        rc_i, i_out, i_err, _ = adb_run(adb_bin, emu_serial, "install", "-r", str(mobile_apk), timeout=60.0)
        if rc_i != 0:
            return emu_serial, started_proc, f"Falha ao instalar APK original no emulador: {i_out} {i_err}"

    return emu_serial, started_proc, "OK"


def _send_gdb_continue(host_port: int) -> tuple[bool, str]:
    """Envia comando RSP continue ($c#63) para tirar o processo anexado pelo lldb-server do estado SIGSTOP."""
    try:
        with socket.create_connection(("127.0.0.1", host_port), timeout=3.0) as sock:
            sock.settimeout(0.6)
            try:
                sock.recv(1024)
            except socket.timeout:
                pass
            sock.sendall(b"+$c#63")
            time.sleep(0.2)
            try:
                ack = sock.recv(1024)
                return True, repr(ack[:64])
            except socket.timeout:
                return True, "sent $c#63 (running)"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def _resolve_frida_device(adb_bin: str, emu_serial: str) -> tuple[Any, bool]:
    import frida  # type: ignore

    try:
        dev = frida.get_device(emu_serial, timeout=6)
        return dev, False
    except Exception:
        adb_run(adb_bin, emu_serial, "forward", "tcp:27042", "tcp:27042")
        dev = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
        return dev, True


def executar_testes_mobile_emulador(
    adb_bin: str,
    emu_serial: str,
    frida_server_bin: Path,
    lldb_server_bin: Path | None,
) -> list[CheckResult]:
    results: list[CheckResult] = []
    _, abi_out, _, _ = adb_run(adb_bin, emu_serial, "shell", "getprop", "ro.product.cpu.abi")
    _, dbg_out, _, _ = adb_run(adb_bin, emu_serial, "shell", "getprop", "ro.debuggable")
    abi = abi_out.strip()
    ro_dbg = dbg_out.strip()

    # ------------------------------------------------------------------
    # M-EMU-1: Detecção de Root, Artefatos de Magisk e Emulador (APK Original)
    # ------------------------------------------------------------------
    created_markers = False
    try:
        adb_run(adb_bin, emu_serial, "shell", "mkdir -p /data/adb/magisk && touch /data/local/su && chmod 755 /data/local/su")
        created_markers = True
        adb_run(adb_bin, emu_serial, "shell", "am", "force-stop", MOBILE_PACKAGE)
        time.sleep(1.0)
        adb_run(adb_bin, emu_serial, "shell", "am", "start", "-n", MOBILE_MAIN_ACTIVITY, timeout=15.0)
        time.sleep(2.5)
        if adb_get_pid(adb_bin, emu_serial):
            ui_texts, clicked = adb_open_vote_link_and_confirm(
                adb_bin,
                emu_serial,
                "EMU_ROOT_MAGISK_PROBE",
                user_zero=False,
            )
        else:
            ui_texts, clicked = [], False
        pids_after = adb_get_pid(adb_bin, emu_serial)
        detected_root_ui = any(
            any(k in t.lower() for k in ("root detectado", "integridade", "depuração", "acesso bloqueado"))
            for t in ui_texts
        )
        terminated = len(pids_after) == 0
        # Critério estrito do Teste 7 exige encerramento imediato ao detectar root/Magisk
        status_e1 = "PASSOU" if terminated else ("FALHOU" if detected_root_ui or pids_after else "FALHOU")
        summary_e1 = (
            "Aplicativo detectou root/Magisk/emulador e encerrou imediatamente sua execução."
            if terminated
            else (
                f"App detectou ambiente comprometido e bloqueou a cédula na UI, porém NÃO encerrou o processo (PIDs={pids_after})."
                if detected_root_ui
                else f"App permaneceu em execução sem exibir bloqueio de root/Magisk (PIDs={pids_after})."
            )
        )
        results.append(
            CheckResult(
                "M-EMU-1",
                f"Mobile Emulador ({emu_serial}, {abi}) | Detecção de Root, Magisk e Emulador",
                status_e1,
                summary_e1,
                [
                    f"Ambiente emulador: uid=0(root), ro.debuggable={ro_dbg}, marcadores temporários=/data/local/su e /data/adb/magisk",
                    f"Deep link confirmado na UI={clicked} | Bloqueio exibido na UI={detected_root_ui}",
                    f"Textos UI capturados: {[t for t in ui_texts if any(w in t.lower() for w in ('root', 'bloqueado', 'integridade', 'depura', 'emulador', 'vota'))][:6]}",
                    f"Processo autoencerrou={terminated} (PIDs={pids_after}) — nota: verificarTudo() bloqueia o acesso à votação, mas não chama finishAffinity()/exitProcess.",
                ],
            )
        )
    finally:
        adb_run(adb_bin, emu_serial, "shell", "am", "force-stop", MOBILE_PACKAGE)
        if created_markers:
            adb_run(adb_bin, emu_serial, "shell", "rm -rf /data/local/su /data/adb/magisk")

    # ------------------------------------------------------------------
    # M-EMU-2: Anexo Direto de Depurador Nativo (lldb-server -> TracerPid != 0)
    # ------------------------------------------------------------------
    lldb_client_bin = find_lldb_client()
    if lldb_server_bin and lldb_server_bin.is_file():
        remote_lldb = "/data/local/tmp/lldb-server"
        fwd_port = find_free_tcp_port()
        lldb_proc: subprocess.Popen[str] | None = None
        lldb_cli_proc: subprocess.Popen[str] | None = None
        try:
            adb_run(adb_bin, emu_serial, "push", str(lldb_server_bin), remote_lldb, timeout=30.0)
            adb_run(adb_bin, emu_serial, "shell", "chmod", "755", remote_lldb)
            adb_run(adb_bin, emu_serial, "shell", "am", "force-stop", MOBILE_PACKAGE)
            time.sleep(1.0)
            adb_run(adb_bin, emu_serial, "shell", "am", "start", "-W", "-n", MOBILE_MAIN_ACTIVITY, timeout=20.0)
            time.sleep(3.0)
            pids_before = adb_get_pid(adb_bin, emu_serial)
            if not pids_before:
                results.append(
                    CheckResult(
                        "M-EMU-2",
                        "Mobile Emulador | Anexo de Depurador Nativo (lldb-server / TracerPid)",
                        "FALHOU",
                        "Não foi possível obter PID ativo do aplicativo antes do anexo do lldb-server.",
                    )
                )
            else:
                target_pid = pids_before[0]
                lldb_proc = subprocess.Popen(
                    [adb_bin, "-s", emu_serial, "shell", remote_lldb, "gdbserver", "127.0.0.1:5039", "--attach", str(target_pid)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                tracer_pid_val = 0
                proc_state = ""
                for _ in range(20):
                    _, st_out, _, _ = adb_run(adb_bin, emu_serial, "shell", "cat", f"/proc/{target_pid}/status")
                    for ln in st_out.splitlines():
                        if ln.startswith("TracerPid:"):
                            tracer_pid_val = int(ln.split(":", 1)[1].strip() or "0")
                        elif ln.startswith("State:"):
                            proc_state = ln.split(":", 1)[1].strip()
                    if tracer_pid_val != 0:
                        break
                    time.sleep(0.25)

                # Garante que lldb-server já abriu o listener TCP 127.0.0.1:5039
                time.sleep(1.5)
                adb_run(adb_bin, emu_serial, "forward", f"tcp:{fwd_port}", "tcp:5039")
                if lldb_client_bin and lldb_client_bin.is_file():
                    lldb_cli_proc = subprocess.Popen(
                        [
                            str(lldb_client_bin),
                            "-o",
                            f"gdb-remote 127.0.0.1:{fwd_port}",
                            "-o",
                            "process handle SIGSEGV -p true -s false -n false",
                            "-o",
                            "process handle SIGBUS -p true -s false -n false",
                            "-o",
                            "process handle SIGILL -p true -s false -n false",
                            "-o",
                            "process handle SIGUSR1 -p true -s false -n false",
                            "-o",
                            "process handle SIGUSR2 -p true -s false -n false",
                            "-o",
                            "process continue",
                        ],
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        start_new_session=True,
                    )
                    time.sleep(0.5)
                    cli_alive = lldb_cli_proc.poll() is None
                    cont_ok = cli_alive
                    cont_msg = f"lldb.sh conectado em 127.0.0.1:{fwd_port} + process continue (cli_alive={cli_alive})"
                else:
                    cont_ok, cont_msg = _send_gdb_continue(fwd_port)
                    time.sleep(0.5)

                auto_terminated_by_watchdog = False
                st_lines: list[str] = []
                state_running = False
                for _ in range(15):
                    time.sleep(0.2)
                    if target_pid not in adb_get_pid(adb_bin, emu_serial):
                        auto_terminated_by_watchdog = True
                        break
                    _, st_raw_cont, _, _ = adb_run(adb_bin, emu_serial, "shell", "cat", f"/proc/{target_pid}/status")
                    st_lines = [
                        ln for ln in st_raw_cont.splitlines() if ln.startswith(("State:", "TracerPid:"))
                    ]
                    has_tracer_running = any(
                        ln.startswith("TracerPid:") and ln.split(":", 1)[1].strip() not in ("", "0")
                        for ln in st_lines
                    )
                    not_stopped = not any("State:\tt" in ln or "tracing stop" in ln.lower() for ln in st_lines)
                    if st_lines and has_tracer_running and not_stopped:
                        state_running = True

                st_after_cont = "\n".join(st_lines)
                if auto_terminated_by_watchdog:
                    alive_before_resume = False
                    pids_after_resume = adb_get_pid(adb_bin, emu_serial)
                    resumed_lines = []
                    activity_closed = True
                    pid_exited = True
                    closed_on_resume = True
                else:
                    # Testa se watchdog contínuo fecha sozinho sem onResume
                    time.sleep(1.5)
                    alive_before_resume = target_pid in adb_get_pid(adb_bin, emu_serial)
                    if not alive_before_resume:
                        auto_terminated_by_watchdog = True

                    # Força onResume() (sem -W para não bloquear caso debugger interrompa em sinal)
                    adb_run(adb_bin, emu_serial, "shell", "input", "keyevent", "KEYCODE_HOME")
                    time.sleep(1.0)
                    adb_run(adb_bin, emu_serial, "shell", "am", "start", "-n", MOBILE_MAIN_ACTIVITY, timeout=12.0)
                    time.sleep(3.0)

                    pids_after_resume = adb_get_pid(adb_bin, emu_serial)
                    _, top_act, _, _ = adb_run(adb_bin, emu_serial, "shell", "dumpsys", "activity", "activities")
                    resumed_lines = [ln.strip() for ln in top_act.splitlines() if "mResumedActivity" in ln or "topResumedActivity" in ln]
                    activity_closed = not any(MOBILE_PACKAGE in ln for ln in resumed_lines)
                    pid_exited = target_pid not in pids_after_resume
                    closed_on_resume = pid_exited or activity_closed

                status_e2 = (
                    "PASSOU"
                    if (tracer_pid_val != 0 and (auto_terminated_by_watchdog or (state_running and closed_on_resume)))
                    else "FALHOU"
                )
                results.append(
                    CheckResult(
                        "M-EMU-2",
                        "Mobile Emulador | Anexo de Depurador Nativo (lldb-server / ptrace -> TracerPid)",
                        status_e2,
                        (
                            f"Depurador nativo anexado (TracerPid={tracer_pid_val}); app encerrou execução imediatamente ao retomar "
                            f"(autoencerrou pelo watchdog nativo={auto_terminated_by_watchdog}, closed_on_resume={closed_on_resume})."
                            if status_e2 == "PASSOU"
                            else f"Falha no anti-debugging para TracerPid={tracer_pid_val} (state_running={state_running}, auto_terminated={auto_terminated_by_watchdog}, activity_closed={activity_closed}, pid_exited={pid_exited})."
                        ),
                        [
                            f"PID alvo={target_pid} | TracerPid={tracer_pid_val} | State ao anexar='{proc_state}'",
                            f"Retomada sob depurador: ok={cont_ok} ({cont_msg}) | state_running={state_running} | Status em execução: {' | '.join(st_after_cont.splitlines()) or 'encerrado pelo watchdog'}",
                            f"Autoencerrou em foreground sem onResume={not alive_before_resume} (watchdog_nativo={auto_terminated_by_watchdog})",
                            f"Após onResume: pid_exited={pid_exited} (PIDs={pids_after_resume}), activity_closed={activity_closed}, top={resumed_lines[:2]}",
                        ],
                    )
                )
        finally:
            if lldb_cli_proc and lldb_cli_proc.poll() is None:
                try:
                    os.killpg(lldb_cli_proc.pid, signal.SIGKILL)
                except OSError:
                    lldb_cli_proc.kill()
            if lldb_proc and lldb_proc.poll() is None:
                lldb_proc.terminate()
                try:
                    lldb_proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    lldb_proc.kill()
            adb_run(adb_bin, emu_serial, "shell", "pkill -9 lldb-server || true")
            adb_run(adb_bin, emu_serial, "forward", "--remove", f"tcp:{fwd_port}")
            adb_run(adb_bin, emu_serial, "shell", "am", "force-stop", MOBILE_PACKAGE)
            adb_run(adb_bin, emu_serial, "shell", "rm -f", remote_lldb)
    else:
        results.append(
            CheckResult(
                "M-EMU-2",
                "Mobile Emulador | Anexo de Depurador Nativo (lldb-server)",
                "N/A",
                "lldb-server x86_64 não encontrado no NDK.",
            )
        )

    # ------------------------------------------------------------------
    # M-EMU-3: Frida Server — Detecção Nativa (3a) e Sobreposição/Bypass (3b)
    # ------------------------------------------------------------------
    if not frida_server_bin.is_file():
        results.append(CheckResult("M-EMU-3", "Mobile Emulador | Frida Server", "N/A", f"frida-server ausente em {frida_server_bin}."))
        return results

    remote_frida = "/data/local/tmp/frida-server"
    frida_proc: subprocess.Popen[str] | None = None
    used_forward = False
    try:
        adb_run(adb_bin, emu_serial, "shell", "pkill -9 frida-server || true")
        adb_run(adb_bin, emu_serial, "shell", "setenforce", "0")
        adb_run(adb_bin, emu_serial, "shell", "setprop", "persist.device_config.runtime_native.usap_pool_enabled", "false")
        adb_run(adb_bin, emu_serial, "push", str(frida_server_bin), remote_frida, timeout=45.0)
        adb_run(adb_bin, emu_serial, "shell", "chmod", "755", remote_frida)

        # ---- Subensaio 3a: Inicia app limpo antes do frida-server, depois sobe frida-server e tenta attach ----
        adb_run(adb_bin, emu_serial, "shell", "am", "force-stop", MOBILE_PACKAGE)
        time.sleep(0.8)
        adb_run(adb_bin, emu_serial, "shell", "am", "start", "-W", "-n", MOBILE_MAIN_ACTIVITY, timeout=20.0)
        time.sleep(2.5)
        pids_3a = adb_get_pid(adb_bin, emu_serial)
        if not pids_3a:
            raise RuntimeError("App encerrou antes mesmo de subir frida-server em 3a.")
        pid_3a = pids_3a[0]

        frida_proc = subprocess.Popen(
            [adb_bin, "-s", emu_serial, "shell", remote_frida, "-l", "0.0.0.0:27042"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        time.sleep(2.5)
        if not adb_get_pid(adb_bin, emu_serial, "frida-server"):
            raise RuntimeError("frida-server não permaneceu ativo no emulador.")

        dev, used_forward = _resolve_frida_device(adb_bin, emu_serial)

        probe_msgs: list[dict[str, Any]] = []
        probe_done = threading.Event()
        attach_3a_error: str | None = None
        session_3a = None
        script_3a = None
        if pid_3a not in adb_get_pid(adb_bin, emu_serial):
            closed_3a = True
            pids_3a_after = adb_get_pid(adb_bin, emu_serial)
            attach_3a_error = "Processo autoencerrou pelo watchdog nativo ao detectar porta/serviço Frida."
        else:
            try:
                session_3a = dev.attach(pid_3a)
                js_probe = """
                Java.perform(function () {
                  try {
                    var SecNat = Java.use('com.meuapptestecripto.SegurancaNativa');
                    var secInst = SecNat.INSTANCE.value;
                    var Verif = Java.use('com.meuapptestecripto.VerificadorSegurancaAndroid');
                    var AppThread = Java.use('android.app.ActivityThread');
                    var ctx = AppThread.currentApplication().getApplicationContext();

                    var nat = {
                      tracerPid: secInst.detectarTracerPidSeguro(),
                      hooksMemoria: secInst.detectarHooksMemoriaSeguro(),
                      descritoresSuspeitos: secInst.detectarDescritoresSuspeitosSeguro(),
                      threadsSuspeitas: secInst.detectarThreadsSuspeitasSeguro(),
                      portaFrida: secInst.detectarPortaFridaSeguro(),
                      rootArquivos: secInst.detectarRootArquivosSeguro(),
                      montagemSuspeita: secInst.detectarMontagemSuspeitaSeguro()
                    };
                    var crit = Verif.verificarDepuracaoCritica();
                    var res = Verif.verificarTudo(ctx);
                    var motivos = [];
                    var it = res.getMotivosBloqueio().iterator();
                    while (it.hasNext()) motivos.push(String(it.next()));

                    send({
                      phase: 'probe',
                      nativa: nat,
                      depuracaoCritica: crit,
                      seguro: res.getSeguro(),
                      categoria: String(res.getCategoriaPrincipal()),
                      motivos: motivos,
                      detalhesDepuracao: String(res.getDetalhesDepuracao().toString()),
                      detalhesRoot: String(res.getDetalhesRoot().toString()),
                      detalhesAdulteracao: String(res.getDetalhesAdulteracao().toString())
                    });
                  } catch (e) {
                    send({ phase: 'probe_error', error: String(e) });
                  }
                });
                """
                script_3a = session_3a.create_script(js_probe)

                def _on_msg_3a(msg: dict[str, Any], _data: Any) -> None:
                    if msg.get("type") == "send":
                        probe_msgs.append(msg.get("payload", {}))
                        probe_done.set()
                    elif msg.get("type") == "error":
                        probe_msgs.append({"phase": "script_error", "error": msg.get("description")})
                        probe_done.set()

                script_3a.on("message", _on_msg_3a)
                script_3a.load()
                probe_done.wait(timeout=8.0)

                # Sem aplicar bypass, dispara onResume com Frida anexado para verificar autoencerramento
                adb_run(adb_bin, emu_serial, "shell", "input", "keyevent", "KEYCODE_HOME")
                time.sleep(1.0)
                adb_run(adb_bin, emu_serial, "shell", "am", "start", "-n", MOBILE_MAIN_ACTIVITY, timeout=15.0)
                time.sleep(2.5)
                pids_3a_after = adb_get_pid(adb_bin, emu_serial)
                _, top_3a, _, _ = adb_run(adb_bin, emu_serial, "shell", "dumpsys", "activity", "activities")
                resumed_3a = [ln.strip() for ln in top_3a.splitlines() if "mResumedActivity" in ln or "topResumedActivity" in ln]
                closed_3a = (pid_3a not in pids_3a_after) or (not any(MOBILE_PACKAGE in ln for ln in resumed_3a))
            except Exception as exc_3a:
                attach_3a_error = f"{type(exc_3a).__name__}: {exc_3a}"
                pids_3a_after = adb_get_pid(adb_bin, emu_serial)
                closed_3a = pid_3a not in pids_3a_after
            finally:
                try:
                    if script_3a is not None:
                        script_3a.unload()
                    if session_3a is not None:
                        session_3a.detach()
                except Exception:
                    pass

        # ---- Subensaio 3b: Spawn + tentativa de sobreposição dos métodos de integridade ----
        adb_run(adb_bin, emu_serial, "shell", "am", "force-stop", MOBILE_PACKAGE)
        time.sleep(0.5)
        bypass_events: list[dict[str, Any]] = []
        spawn_pid = dev.spawn([MOBILE_PACKAGE])
        session_3b = None
        script_3b = None
        spawn_3b_error: str | None = None
        try:
            session_3b = dev.attach(spawn_pid)
            js_bypass = """
            Java.perform(function () {
              try {
                var SecNat = Java.use('com.meuapptestecripto.SegurancaNativa');
                var Verif = Java.use('com.meuapptestecripto.VerificadorSegurancaAndroid');
                var Resultado = Java.use('com.meuapptestecripto.VerificadorSegurancaAndroid$ResultadoSeguranca');
                var ArrayList = Java.use('java.util.ArrayList');
                var LinkedHashMap = Java.use('java.util.LinkedHashMap');

                var natMethods = [
                  'nativeDetectarTracerPid',
                  'nativeDetectarHooksMemoria',
                  'nativeDetectarDescritoresSuspeitos',
                  'nativeDetectarThreadsSuspeitas',
                  'nativeDetectarPortaFrida',
                  'nativeDetectarRootArquivos',
                  'nativeDetectarMontagemSuspeita'
                ];
                natMethods.forEach(function (m) {
                  SecNat[m].implementation = function () {
                    var orig = this[m]();
                    send({ event: 'override_native', method: m, orig: orig, forced: false });
                    return false;
                  };
                });

                Verif.verificarDepuracaoCritica.implementation = function () {
                  var orig = this.verificarDepuracaoCritica();
                  send({ event: 'override_critica', orig: orig, forced: false });
                  return false;
                };

                Verif.verificarTudo.implementation = function (ctx) {
                  var orig = this.verificarTudo(ctx);
                  var motivos = [];
                  var it = orig.getMotivosBloqueio().iterator();
                  while (it.hasNext()) motivos.push(String(it.next()));
                  send({
                    event: 'override_tudo',
                    origSeguro: orig.getSeguro(),
                    origCategoria: String(orig.getCategoriaPrincipal()),
                    origMotivos: motivos
                  });
                  return Resultado.$new(
                    true,
                    'ok',
                    'Integridade Verificada',
                    'Bypassed via Frida Hook',
                    ArrayList.$new(),
                    LinkedHashMap.$new(),
                    LinkedHashMap.$new(),
                    LinkedHashMap.$new()
                  );
                };
                send({ event: 'hooks_installed' });
              } catch (e) {
                send({ event: 'hook_error', error: String(e) });
              }
            });
            """
            script_3b = session_3b.create_script(js_bypass)
            hooks_ready = threading.Event()

            def _on_msg_3b(msg: dict[str, Any], _data: Any) -> None:
                if msg.get("type") == "send":
                    pl = msg.get("payload", {})
                    bypass_events.append(pl)
                    if pl.get("event") in ("hooks_installed", "hook_error"):
                        hooks_ready.set()
                elif msg.get("type") == "error":
                    bypass_events.append({"event": "script_error", "error": msg.get("description")})

            script_3b.on("message", _on_msg_3b)
            script_3b.load()
            dev.resume(spawn_pid)
            hooks_ready.wait(timeout=8.0)
            time.sleep(3.0)
        except Exception as exc_3b:
            spawn_3b_error = f"{type(exc_3b).__name__}: {exc_3b}"

        if spawn_pid in adb_get_pid(adb_bin, emu_serial):
            ui_3b, clicked_3b = adb_open_vote_link_and_confirm(
                adb_bin,
                emu_serial,
                "FRIDA_OVERRIDE_BYPASS_TEST",
                user_zero=False,
            )
        else:
            ui_3b, clicked_3b = [], False

        pids_3b = adb_get_pid(adb_bin, emu_serial)
        app_survived_bypass = spawn_pid in pids_3b
        blocked_integrity_3b = any(
            any(k in t.lower() for k in ("depuração ou instrumentação", "root detectado", "integridade do aplicativo comprometida"))
            for t in ui_3b
        )
        reached_keystore_stage_3b = any(
            any(k in t.lower() for k in ("emulação por software", "votar", "cédula"))
            for t in ui_3b
        )

        try:
            if script_3b is not None:
                script_3b.unload()
            if session_3b is not None:
                session_3b.detach()
        except Exception:
            pass

        probe_info = probe_msgs[0] if probe_msgs else {}
        nat_detected = probe_info.get("nativa", {})
        override_native_cnt = sum(1 for e in bypass_events if e.get("event") == "override_native")
        override_crit_cnt = sum(1 for e in bypass_events if e.get("event") == "override_critica")
        override_tudo_evts = [e for e in bypass_events if e.get("event") == "override_tudo"]
        hook_errors = [e for e in bypass_events if e.get("event") in ("hook_error", "script_error")]
        bypass_succeeded = (
            app_survived_bypass
            and (not blocked_integrity_3b)
            and bool(override_tudo_evts or override_crit_cnt > 0 or override_native_cnt > 0)
        )

        details_3: list[str] = [
            f"3a (Attach após start limpo): closed_on_resume={closed_3a} | PIDs após={pids_3a_after} | err={attach_3a_error or 'nenhum'}",
            f"3a Detectores nativos: {json.dumps(nat_detected, ensure_ascii=False)}",
            f"3a VerificadorSegurancaAndroid.verificarTudo: seguro={probe_info.get('seguro')}, cat={probe_info.get('categoria')}, motivos={probe_info.get('motivos')}",
            f"3b (Spawn + Sobreposição Frida): spawn_pid={spawn_pid}, app_vivo={app_survived_bypass}, bloqueio_integridade_ui={blocked_integrity_3b}, alcancou_etapa_keystore={reached_keystore_stage_3b}, deep_link_confirmado={clicked_3b}, err={spawn_3b_error or 'nenhum'}",
            f"3b Métodos interceptados/sobrescritos: native*={override_native_cnt}x, verificarDepuracaoCritica={override_crit_cnt}x, verificarTudo={len(override_tudo_evts)}x, erros_hook={hook_errors}",
        ]
        if override_tudo_evts:
            details_3.append(
                f"3b Resultado original suprimido em verificarTudo(): {json.dumps(override_tudo_evts[0], ensure_ascii=False)}"
            )
        details_3.append(f"3b Textos UI sob hook Frida: {ui_3b[:8]}")

        if bypass_succeeded:
            status_e3 = "FALHOU"
            summary_e3 = (
                "Detectores nativos (3a) identificaram o Frida quando sem bypass, porém em 3b o Frida "
                "injetou no spawn e sobrescreveu VerificadorSegurancaAndroid/SegurancaNativa, impedindo o encerramento."
            )
        elif closed_3a and not app_survived_bypass:
            status_e3 = "PASSOU"
            summary_e3 = (
                "Aplicativo detectou os ganchos/ambiente do Frida (3a) e encerrou imediatamente sua execução no spawn (3b), "
                "impedindo a sobreposição das validações de integridade."
            )
        elif not app_survived_bypass:
            status_e3 = "PASSOU"
            summary_e3 = "Aplicativo detectou os ganchos do Frida e encerrou sua execução mesmo após tentativa de sobreposição."
        else:
            status_e3 = "FALHOU"
            summary_e3 = "Aplicativo não encerrou sob instrumentação do Frida."

        results.append(
            CheckResult(
                "M-EMU-3",
                "Mobile Emulador | Frida Server — Detecção e Sobreposição Dinâmica (APK Original)",
                status_e3,
                summary_e3,
                details_3,
            )
        )
    except Exception as exc:
        results.append(
            CheckResult(
                "M-EMU-3",
                "Mobile Emulador | Frida Server — Detecção e Sobreposição Dinâmica",
                "FALHOU",
                f"Erro durante execução com frida-server: {type(exc).__name__}: {exc}",
            )
        )
    finally:
        if frida_proc and frida_proc.poll() is None:
            frida_proc.terminate()
            try:
                frida_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                frida_proc.kill()
        adb_run(adb_bin, emu_serial, "shell", "pkill -9 frida-server || true")
        if used_forward:
            adb_run(adb_bin, emu_serial, "forward", "--remove", "tcp:27042")
        adb_run(adb_bin, emu_serial, "shell", "am", "force-stop", MOBILE_PACKAGE)
        adb_run(adb_bin, emu_serial, "shell", "rm -f", remote_frida)
        adb_run(adb_bin, emu_serial, "shell", "setenforce", "1")

    return results


# ==============================================================================
# CLI e Orquestração Principal
# ==============================================================================
def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Teste 7 (Eixo 3): Instrumentação Dinâmica com Frida e Anti-Debugging (instalações originais)."
    )
    p.add_argument(
        "--target",
        choices=("all", "desktop", "mobile-physical", "mobile-emulator"),
        default="all",
        help="Alvo(s) do ensaio (padrão: all).",
    )
    p.add_argument("--desktop-bin", type=Path, default=DEFAULT_DESKTOP_BIN, help="Executável PyInstaller do módulo administrativo.")
    p.add_argument("--desktop-python", type=Path, default=DESKTOP_VENV_PYTHON, help="Python do venv do votaai-desktop (para D4).")
    p.add_argument("--mobile-apk", type=Path, default=DEFAULT_MOBILE_APK, help="APK release original (usado apenas no emulador se ausente).")
    p.add_argument("--physical-serial", default=None, help="Serial ADB do smartphone físico sem root.")
    p.add_argument("--emulator-serial", default=None, help="Serial ADB do emulador Android com root.")
    p.add_argument("--avd", default=DEFAULT_AVD_NAME, help=f"Nome do AVD para --auto-start-emulator (padrão: {DEFAULT_AVD_NAME}).")
    p.add_argument("--auto-start-emulator", action="store_true", help="Inicia o AVD headless automaticamente se nenhum emulador estiver online.")
    p.add_argument("--keep-emulator", action="store_true", help="Não desliga o emulador iniciado automaticamente ao final.")
    p.add_argument("--frida-server", type=Path, default=DEFAULT_FRIDA_SERVER, help="Caminho do binário frida-server android-x86_64.")
    p.add_argument("--lldb-server", type=Path, default=None, help="Caminho do lldb-server x86_64 do Android NDK.")
    p.add_argument("--json-out", type=Path, default=None, help="Grava relatório completo em JSON.")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    adb_bin = find_adb()
    lldb_bin = find_lldb_server(args.lldb_server)

    physical_devs, emulator_devs = list_adb_devices(adb_bin)
    phys_serial = args.physical_serial or (physical_devs[0] if physical_devs else None)
    emu_serial_req = args.emulator_serial or (emulator_devs[0] if emulator_devs else None)

    checks: list[CheckResult] = []
    started_emu_proc: subprocess.Popen[bytes] | None = None
    active_emu_serial: str | None = None

    try:
        if args.target in ("all", "desktop"):
            checks.extend(executar_testes_desktop(args.desktop_bin, args.desktop_python))

        if args.target in ("all", "mobile-physical"):
            if phys_serial:
                checks.extend(executar_testes_mobile_fisico(adb_bin, phys_serial))
            else:
                checks.append(
                    CheckResult(
                        "M-FIS-1",
                        "Mobile Físico | Dispositivo",
                        "N/A",
                        "Nenhum smartphone físico conectado via ADB.",
                    )
                )

        if args.target in ("all", "mobile-emulator"):
            active_emu_serial, started_emu_proc, emu_msg = ensure_emulator_ready(
                adb_bin,
                DEFAULT_EMULATOR_BIN,
                args.avd,
                emu_serial_req,
                args.auto_start_emulator,
                args.mobile_apk,
            )
            if emu_msg != "OK" or not active_emu_serial:
                checks.append(
                    CheckResult(
                        "M-EMU-1",
                        "Mobile Emulador | Preparação AVD Root",
                        "FALHOU" if args.auto_start_emulator or emu_serial_req else "N/A",
                        emu_msg,
                    )
                )
            else:
                checks.extend(
                    executar_testes_mobile_emulador(
                        adb_bin,
                        active_emu_serial,
                        args.frida_server,
                        lldb_bin,
                    )
                )

        print("\n" + "=" * 82)
        print("ENSAIO DE INSTRUMENTAÇÃO DINÂMICA COM FRIDA E ANTI-DEBUGGING (EIXO 3 - TESTE 7)")
        print("Escopo: Instalações e binários originais (sem reempacotamento de APK)")
        print("=" * 82)
        print(f"Desktop Bin   : {args.desktop_bin}")
        print(f"Físico (ADB)  : {phys_serial or 'N/A'}")
        print(f"Emulador (ADB): {active_emu_serial or emu_serial_req or 'N/A'}")
        print(f"Frida Server  : {args.frida_server}")
        print(f"LLDB Server   : {lldb_bin or 'N/A'}")
        print("-" * 82)
        for chk in checks:
            print(f"[{chk.status:<6}] {chk.code:<7} - {chk.title}: {chk.summary}")
            for line in chk.details:
                print(f"           {line}")
        print("-" * 82)

        def _group_status(prefix: str) -> str:
            grp = [c for c in checks if c.code.startswith(prefix)]
            if not grp or all(c.status == "N/A" for c in grp):
                return "N/A"
            if any(c.status == "FALHOU" for c in grp):
                return "REPROVADO"
            if any(c.status == "ALERTA" for c in grp):
                return "PARCIAL (COM ALERTAS)"
            return "APROVADO"

        summary_groups = {
            "desktop_admin": _group_status("D"),
            "mobile_physical_nonroot": _group_status("M-FIS"),
            "mobile_emulator_root": _group_status("M-EMU"),
        }
        verdict = "REPROVADO" if any(c.status == "FALHOU" for c in checks) else "APROVADO"

        print("RESUMO POR ALVO:")
        print(f"  - Módulo Administrativo (votaai-desktop / GDB / Watchdog) : {summary_groups['desktop_admin']}")
        print(f"  - Aplicativo Móvel Físico Sem Root (APK original)         : {summary_groups['mobile_physical_nonroot']}")
        print(f"  - Aplicativo Móvel Emulador Com Root (APK original)       : {summary_groups['mobile_emulator_root']}")
        print("=" * 82)
        print(f"Veredito Final (Critério Estrito Teste 7): {verdict}")

        if args.json_out:
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            report = {
                "verdict": verdict,
                "summary_by_target": summary_groups,
                "environment": {
                    "desktop_bin": str(args.desktop_bin),
                    "physical_serial": phys_serial,
                    "emulator_serial": active_emu_serial or emu_serial_req,
                    "frida_server": str(args.frida_server),
                    "lldb_server": str(lldb_bin) if lldb_bin else None,
                },
                "checks": [asdict(c) for c in checks],
            }
            args.json_out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
            print(f"Relatório JSON salvo em: {args.json_out}")

        return 0 if verdict == "APROVADO" else 1
    finally:
        if started_emu_proc is not None and not args.keep_emulator:
            if active_emu_serial:
                adb_run(adb_bin, active_emu_serial, "emu", "kill", timeout=15.0)
            try:
                started_emu_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                started_emu_proc.terminate()


if __name__ == "__main__":
    raise SystemExit(main())
