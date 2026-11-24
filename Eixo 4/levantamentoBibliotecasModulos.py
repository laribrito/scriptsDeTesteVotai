"""
Teste 10 (Eixo 4): Levantamento e Analise de Bibliotecas e Modulos de Terceiros

Inventaria as dependencias do backend Django, da interface PyQt e do React Native,
consulta bases publicas de vulnerabilidades (OSV/npm advisory) e avalia controles
basicos de menor privilegio e cadeia de suprimentos.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
BACKEND_ROOT = Path("/home/debrito/Programação/votaai-backend")
DESKTOP_ROOT = Path("/home/debrito/Programação/votaai-desktop")
MOBILE_ROOT = Path("/home/debrito/Programação/projeto-react-native")


@dataclass
class CheckResult:
    code: str
    title: str
    status: str
    summary: str
    details: list[str] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)


def post_json(url: str, payload: dict[str, Any], timeout: float = 30.0) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "votaai-dependency-audit/1.0"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def parse_requirements(path: Path) -> list[dict[str, str]]:
    packages: list[dict[str, str]] = []
    if not path.is_file():
        return packages
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        name = line
        version = ""
        if "===" in line:
            name, version = (part.strip() for part in line.split("===", 1))
            version = f"=== {version}"
        elif "==" in line:
            name, version = (part.strip() for part in line.split("==", 1))
        elif ">=" in line:
            name, version = (part.strip() for part in line.split(">=", 1))
            version = f">={version}"
        elif "~=" in line:
            name, version = (part.strip() for part in line.split("~=", 1))
            version = f"~={version}"
        packages.append({"name": name, "version": version})
    return packages


def osv_python_vulnerabilities(packages: list[dict[str, str]]) -> tuple[list[dict[str, Any]], str]:
    pinned = [item for item in packages if item["version"] and not item["version"].startswith((">=", "~=", "==="))]
    if not pinned:
        return [], "nenhuma versao Python fixa disponivel para consulta"

    queries = [
        {
            "package": {"name": item["name"], "ecosystem": "PyPI"},
            "version": item["version"],
        }
        for item in pinned
    ]
    try:
        data = post_json("https://api.osv.dev/v1/querybatch", {"queries": queries}, timeout=60)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        return [], f"consulta OSV indisponivel: {exc}"

    findings: list[dict[str, Any]] = []
    for package, result in zip(pinned, data.get("results", [])):
        for vulnerability in result.get("vulns", []):
            findings.append({
                "name": package["name"],
                "version": package["version"],
                "id": vulnerability.get("id", ""),
                "aliases": vulnerability.get("aliases", []),
                "summary": vulnerability.get("summary", ""),
                "source": "OSV",
            })
    return findings, ""


def npm_audit(root: Path) -> tuple[list[dict[str, Any]], dict[str, Any], str]:
    npm = shutil.which("npm")
    if not npm:
        return [], {}, "npm nao encontrado"
    proc = subprocess.run(
        [npm, "audit", "--omit=dev", "--json"],
        cwd=str(root),
        capture_output=True,
        text=True,
        timeout=120,
    )
    if not proc.stdout:
        return [], {}, f"npm audit sem saida (rc={proc.returncode})"
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return [], {}, f"resposta npm audit invalida: {exc}"

    findings: list[dict[str, Any]] = []
    for name, item in report.get("vulnerabilities", {}).items():
        findings.append({
            "name": name,
            "severity": item.get("severity", "unknown"),
            "range": item.get("range", ""),
            "nodes": item.get("nodes", []),
            "via": [entry.get("name", entry if isinstance(entry, str) else "") for entry in item.get("via", [])],
            "fixAvailable": item.get("fixAvailable"),
            "source": "npm advisory",
        })
    return findings, report.get("metadata", {}).get("vulnerabilities", {}), ""


def package_inventory(root: Path) -> tuple[list[dict[str, str]], dict[str, Any]]:
    package_json = root / "package.json"
    lock_json = root / "package-lock.json"
    direct: dict[str, str] = {}
    if package_json.is_file():
        try:
            manifest = json.loads(package_json.read_text(encoding="utf-8"))
            direct.update(manifest.get("dependencies", {}))
            direct.update(manifest.get("devDependencies", {}))
        except json.JSONDecodeError:
            pass

    packages: list[dict[str, str]] = [{"name": name, "version": version} for name, version in sorted(direct.items())]
    lock_meta: dict[str, Any] = {"lockfile": lock_json.is_file(), "total": 0, "with_integrity": 0}
    if lock_json.is_file():
        try:
            lock = json.loads(lock_json.read_text(encoding="utf-8"))
            lock_packages = lock.get("packages", {})
            lock_meta["total"] = len([name for name in lock_packages if name])
            lock_meta["with_integrity"] = sum(
                1 for name, item in lock_packages.items()
                if name and isinstance(item, dict) and item.get("integrity")
            )
        except json.JSONDecodeError:
            lock_meta["lockfile_valid"] = False
        else:
            lock_meta["lockfile_valid"] = True
    return packages, lock_meta


def least_privilege_and_supply_chain(root: Path) -> tuple[list[str], list[str]]:
    if not root.exists():
        return ["Raiz do projeto indisponivel para auditoria."], []

    findings: list[str] = []
    protections: list[str] = []
    text_sources: list[Path] = []
    for pattern in ("*.py", "*.js", "*.jsx", "*.ts", "*.tsx", "*.gradle", "*.xml"):
        text_sources.extend(root.rglob(pattern))

    broad_patterns = (
        ("chmod 777", "uso de permissao Unix 0777"),
        ("MODE_WORLD_WRITEABLE", "uso de armazenamento Android world-writeable"),
        ("set_world_writeable", "uso de armazenamento world-writeable"),
        ("shell=True", "execucao shell potencialmente ampliada"),
    )
    for path in text_sources:
        if any(part in {".git", ".venv", "node_modules", "build", "dist"} for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for needle, finding in broad_patterns:
            if needle in text:
                findings.append(f"{finding}: {path}")

    for lock_name in ("package-lock.json", "poetry.lock", "Pipfile.lock"):
        if (root / lock_name).is_file():
            protections.append(f"Lockfile presente: {lock_name}")
    requirements = root / "requirements.txt"
    if requirements.is_file():
        packages = parse_requirements(requirements)
        fixed = sum(bool(item["version"] and not item["version"].startswith(">=")) for item in packages)
        protections.append(f"Requisitos Python fixos: {fixed}/{len(packages)}")
        if fixed != len(packages):
            findings.append(f"{len(packages) - fixed} requisito(s) Python nao fixo(s) em requirements.txt")

    if (root / ".github" / "workflows").exists():
        protections.append("Workflows de integracao identificados")
    if (root / ".dockerignore").is_file():
        protections.append(".dockerignore presente")
    return findings, protections


def build_python_check(code: str, title: str, root: Path) -> CheckResult:
    requirements = root / "requirements.txt"
    packages = parse_requirements(requirements)
    vulnerabilities, scanner_error = osv_python_vulnerabilities(packages)
    findings, protections = least_privilege_and_supply_chain(root)
    fixed = sum(bool(item["version"] and not item["version"].startswith(">=")) for item in packages)

    status = "ALERTA"
    if scanner_error:
        status = "ALERTA"
    elif vulnerabilities:
        status = "FALHOU"
    elif findings:
        status = "FALHOU"
    else:
        status = "PASSOU"

    details = [
        f"Pacotes declarados em requirements.txt: {len(packages)}",
        f"Versoes fixas: {fixed}/{len(packages)}",
        f"Vulnerabilidades OSV encontradas: {len(vulnerabilities)}",
    ]
    details.extend(protections)
    details.extend(findings)
    if scanner_error:
        details.append(scanner_error)

    summary = (
        f"{len(vulnerabilities)} vulnerabilidade(s) conhecida(s) ou controle(s) inseguro(s) encontrado(s)."
        if status != "PASSOU"
        else "Nenhuma vulnerabilidade conhecida ou risco basico de menor privilegio/cadeia de suprimentos identificado."
    )
    return CheckResult(
        code,
        title,
        status,
        summary,
        details,
        {
            "declared_packages": len(packages),
            "fixed_versions": fixed,
            "vulnerability_count": len(vulnerabilities),
            "findings": findings,
            "vulnerabilities": vulnerabilities,
        },
    )


def build_mobile_check(root: Path) -> CheckResult:
    packages, lock_meta = package_inventory(root)
    vulnerabilities, vuln_meta, scanner_error = npm_audit(root)
    findings, protections = least_privilege_and_supply_chain(root)

    status = "ALERTA" if scanner_error else ("FALHOU" if vulnerabilities or findings or not lock_meta.get("lockfile_valid") else "PASSOU")
    details = [
        f"Dependencias diretas declaradas: {len(packages)}",
        f"Pacotes totais no lockfile: {lock_meta['total']}",
        f"Pacotes com integridade no lockfile: {lock_meta['with_integrity']}/{lock_meta['total']}",
        f"Advisories npm: {len(vulnerabilities)}",
        f"Severidades: {json.dumps(vuln_meta, ensure_ascii=False)}",
    ]
    details.extend(protections)
    details.extend(findings)
    if scanner_error:
        details.append(scanner_error)
    summary = (
        "Advisories ou falhas basicas de integridade foram encontrados."
        if status == "FALHOU"
        else ("Auditoria incompleta por indisponibilidade da base/ferramenta." if status == "ALERTA"
              else "Nenhuma vulnerabilidade conhecida ou falha basica de integridade foi encontrada.")
    )
    return CheckResult(
        "M10",
        "Mobile React Native | Bibliotecas e Cadeia de Suprimentos",
        status,
        summary,
        details,
        {
            "direct_dependencies": len(packages),
            "lockfile": lock_meta,
            "vulnerability_count": len(vulnerabilities),
            "vulnerability_severity": vuln_meta,
            "findings": findings,
            "vulnerabilities": vulnerabilities,
        },
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Teste 10 (Eixo 4): Levantamento e analise de bibliotecas de terceiros."
    )
    parser.add_argument("--target", choices=("all", "backend", "desktop", "mobile"), default="all")
    parser.add_argument("--backend-root", type=Path, default=BACKEND_ROOT)
    parser.add_argument("--desktop-root", type=Path, default=DESKTOP_ROOT)
    parser.add_argument("--mobile-root", type=Path, default=MOBILE_ROOT)
    parser.add_argument("--json-out", type=Path, default=None)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    checks: list[CheckResult] = []

    if args.target in ("all", "backend"):
        checks.append(build_python_check("B10", "Backend Django | Dependencias de Terceiros", args.backend_root))
    if args.target in ("all", "desktop"):
        checks.append(build_python_check("D10", "Desktop PyQt | Dependencias de Terceiros", args.desktop_root))
    if args.target in ("all", "mobile"):
        checks.append(build_mobile_check(args.mobile_root))

    verdict = (
        "REPROVADO" if any(check.status == "FALHOU" for check in checks)
        else ("APROVADO" if all(check.status == "PASSOU" for check in checks)
              else "PARCIAL (COM ALERTAS)")
    )

    print("\n" + "=" * 86)
    print("ENSAIO DE BIBLIOTECAS E MODULOS DE TERCEIROS (EIXO 4 - TESTE 10)")
    print("Fontes: OSV (PyPI) e npm advisory audit")
    print("=" * 86)
    for check in checks:
        print(f"[{check.status:<6}] {check.code:<4} - {check.title}: {check.summary}")
        for detail in check.details:
            print(f"           {detail}")
    print("-" * 86)
    print("Criterios:")
    print("  1. Nenhuma vulnerabilidade conhecida por CVE/advisory nas dependencias auditadas.")
    print("  2. Menor privilegio observado sem permissoes ou execucoes amplas no codigo-fonte.")
    print("  3. Lockfiles/pins e integridade de artefatos presentes para mitigar cadeia de suprimentos.")
    print("-" * 86)
    print(f"Veredito Final (Teste 10): {verdict}")

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        report = {
            "test": "Teste 10 (Eixo 4) - Levantamento e Analise de Bibliotecas e Modulos de Terceiros",
            "verdict": verdict,
            "checks": [asdict(check) for check in checks],
        }
        args.json_out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Relatorio JSON salvo em: {args.json_out}")

    return 0 if verdict == "APROVADO" else 1


if __name__ == "__main__":
    raise SystemExit(main())
