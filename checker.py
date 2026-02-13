#!/usr/bin/env python3
import argparse
import csv
import json
import re
import subprocess
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple


EXCLUDE_GLOBS = [
    "!**/.git/**",
    "!**/node_modules/**",
    "!**/dist/**",
    "!**/build/**",
    "!**/target/**",
    "!**/vendor/**",
    "!**/.venv/**",
    "!**/venv/**",
    "!**/__pycache__/**",
    "!**/.next/**",
    "!**/.nuxt/**",
    "!**/coverage/**",
    "!**/out/**",
    "!**/bin/**",
    "!**/obj/**",
]

NUMERIC_TYPE_REGEXES = [
    re.compile(r"\b(?:int|integer|long|double|float|bigint|smallint|tinyint|numeric|decimal|number|bigdecimal|biginteger|short|byte)\b.{0,80}\b[a-zA-Z_]*cnpj[a-zA-Z0-9_]*\b", re.IGNORECASE),
    re.compile(r"\b[a-zA-Z_]*cnpj[a-zA-Z0-9_]*\b\s*[:=]\s*(?:int|integer|long|double|float|bigint|numeric|decimal|number|bigdecimal|biginteger)", re.IGNORECASE),
    re.compile(r"\b[a-zA-Z_]*cnpj[a-zA-Z0-9_]*\b\s+\b(?:int|integer|long|double|float|bigint|numeric|decimal|number|bigdecimal)\b", re.IGNORECASE),
    re.compile(r"\b[a-zA-Z_]*cnpj[a-zA-Z0-9_]*\b.{0,50}\b(?:NUMBER|NUMERIC|DECIMAL|BIGINT|INT|INTEGER|SMALLINT|TINYINT)\b", re.IGNORECASE),
]

NUMERIC_PARSE_REGEXES = [
    re.compile(r"(?:parseInt|parseLong|parseFloat|parseDouble|Number\s*\(|BigDecimal\s*\(|BigInteger\s*\(|to_i\b|to_f\b).{0,80}cnpj", re.IGNORECASE),
    re.compile(r"cnpj.{0,80}(?:parseInt|parseLong|parseFloat|parseDouble|Number\s*\(|BigDecimal\s*\(|BigInteger\s*\()", re.IGNORECASE),
    re.compile(r"CAST\s*\(.{0,80}cnpj.{0,80}AS\s+(?:INT|INTEGER|BIGINT|DECIMAL|NUMERIC|NUMBER)", re.IGNORECASE),
]

DIGITS_ONLY_REGEXES = [
    re.compile(r"cnpj.{0,120}(?:\\d\{14\}|\[0-9\]\{14\}|\^\[0-9\]\{14\}\$)", re.IGNORECASE),
    re.compile(r"(?:\\D|\[\^0-9\])", re.IGNORECASE),
    re.compile(r"cnpj.{0,80}replace(?:All)?\s*\(.{0,80}(?:\\D|\[\^0-9\])", re.IGNORECASE),
    re.compile(r"cnpj.{0,80}length\s*[=!]=\s*14", re.IGNORECASE),
    re.compile(r"cnpj.{0,80}len\s*\(.{0,80}\)\s*[=!]=\s*14", re.IGNORECASE),
]

SAFE_STRING_REGEXES = [
    re.compile(r"\b(?:string|varchar|char|text)\b.{0,80}\b[a-zA-Z_]*cnpj[a-zA-Z0-9_]*\b", re.IGNORECASE),
    re.compile(r"\b[a-zA-Z_]*cnpj[a-zA-Z0-9_]*\b\s*[:=]\s*(?:string|str|varchar|char|text)", re.IGNORECASE),
]


@dataclass
class Finding:
    repository: str
    file_path: str
    line: int
    severity: str
    rule_id: str
    message: str
    snippet: str


SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1}


def run_rg(base_dir: Path):
    cmd = [
        "rg",
        "--json",
        "-n",
        "-i",
        "--hidden",
        "--follow",
        "cnpj",
        str(base_dir),
    ]
    for g in EXCLUDE_GLOBS:
        cmd.extend(["-g", g])

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert proc.stdout is not None
    for line in proc.stdout:
        yield line.rstrip("\n")

    stderr = proc.stderr.read() if proc.stderr else ""
    code = proc.wait()
    if code not in (0, 1):
        raise RuntimeError(f"rg falhou (code={code}): {stderr.strip()}")


def discover_repositories(base_dir: Path) -> set:
    repos = set()
    for git_dir in base_dir.rglob(".git"):
        if git_dir.is_dir():
            repos.add(git_dir.parent.resolve())
    return repos


def find_repo_for_file(file_path: Path, base_dir: Path, repos: set, cache: Dict[Path, Optional[Path]]) -> Optional[Path]:
    if file_path in cache:
        return cache[file_path]

    cur = file_path.parent.resolve()
    base_resolved = base_dir.resolve()
    while cur != base_resolved and cur.parent != cur:
        if cur in repos:
            cache[file_path] = cur
            return cur
        cur = cur.parent

    cache[file_path] = None
    return None


def classify_snippet(snippet: str) -> List[Tuple[str, str, str]]:
    findings = []

    for rx in NUMERIC_TYPE_REGEXES:
        if rx.search(snippet):
            findings.append(("high", "numeric_type", "CNPJ modelado como tipo numerico (quebra com alfanumerico)."))
            break

    for rx in NUMERIC_PARSE_REGEXES:
        if rx.search(snippet):
            findings.append(("high", "numeric_parse", "CNPJ sendo convertido para numero (quebra com alfanumerico)."))
            break

    digits_hits = sum(1 for rx in DIGITS_ONLY_REGEXES if rx.search(snippet))
    if digits_hits >= 2:
        findings.append(("high", "digits_only_strict", "Validacao fortemente numerica de CNPJ (provavel quebra)."))
    elif digits_hits == 1:
        findings.append(("medium", "digits_only_hint", "Regra numerica detectada para CNPJ; revisar para alfanumerico."))

    for rx in SAFE_STRING_REGEXES:
        if rx.search(snippet):
            findings.append(("low", "string_model", "CNPJ aparenta estar como texto (tendencia compativel)."))
            break

    if not findings:
        findings.append(("low", "cnpj_reference", "Referencia a CNPJ encontrada; exige revisao contextual."))

    return findings


def analyze(base_dir: Path, include_migracao_ensemble: bool = False) -> List[Finding]:
    base_dir_resolved = base_dir.resolve()
    repos = discover_repositories(base_dir)
    repo_cache: Dict[Path, Optional[Path]] = {}
    findings: List[Finding] = []

    for raw in run_rg(base_dir):
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            continue

        if payload.get("type") != "match":
            continue

        data = payload.get("data", {})
        path_text = data.get("path", {}).get("text")
        line_number = data.get("line_number")
        line_text = data.get("lines", {}).get("text", "").rstrip("\n")
        if not path_text or not line_number:
            continue

        path = Path(path_text)
        repo_path = find_repo_for_file(path, base_dir, repos, repo_cache)
        if not repo_path:
            continue

        repo_rel = str(repo_path.relative_to(base_dir_resolved))
        if not include_migracao_ensemble and repo_rel.startswith("migracao-ensemble/"):
            continue

        for severity, rule_id, message in classify_snippet(line_text):
            findings.append(
                Finding(
                    repository=repo_rel,
                    file_path=str(path.resolve().relative_to(base_dir_resolved)),
                    line=int(line_number),
                    severity=severity,
                    rule_id=rule_id,
                    message=message,
                    snippet=line_text.strip(),
                )
            )

    return findings


def write_outputs(findings: List[Finding], output_dir: Path, base_dir: Path, include_migracao_ensemble: bool):
    output_dir.mkdir(parents=True, exist_ok=True)

    findings_json = output_dir / "findings.json"
    findings_csv = output_dir / "findings.csv"
    summary_md = output_dir / "summary.md"

    findings_payload = [
        {
            "repository": f.repository,
            "file_path": f.file_path,
            "line": f.line,
            "severity": f.severity,
            "rule_id": f.rule_id,
            "message": f.message,
            "snippet": f.snippet,
        }
        for f in findings
    ]

    with findings_json.open("w", encoding="utf-8") as fp:
        json.dump(findings_payload, fp, ensure_ascii=False, indent=2)

    with findings_csv.open("w", newline="", encoding="utf-8") as fp:
        writer = csv.writer(fp, delimiter=";")
        writer.writerow(["repository", "file_path", "line", "severity", "rule_id", "message", "snippet"])
        for f in findings:
            writer.writerow([f.repository, f.file_path, f.line, f.severity, f.rule_id, f.message, f.snippet])

    by_repo: Dict[str, List[Finding]] = defaultdict(list)
    for f in findings:
        by_repo[f.repository].append(f)

    repo_summary = []
    for repo, repo_findings in by_repo.items():
        max_sev = max(repo_findings, key=lambda x: SEVERITY_ORDER[x.severity]).severity
        counts = Counter(x.severity for x in repo_findings)
        repo_summary.append((repo, max_sev, counts["high"], counts["medium"], counts["low"], len(repo_findings)))

    repo_summary.sort(key=lambda x: (-SEVERITY_ORDER[x[1]], -x[2], -x[3], x[0]))

    with summary_md.open("w", encoding="utf-8") as fp:
        fp.write("# Lula Checker IPP 2026 - Relatorio de Risco CNPJ Alfanumerico\n\n")
        fp.write(f"- Data de execucao: {datetime.now().isoformat(timespec='seconds')}\n")
        fp.write(f"- Base analisada: `{base_dir}`\n")
        fp.write(f"- Inclui migracao-ensemble: `{include_migracao_ensemble}`\n")
        fp.write(f"- Total de achados: **{len(findings)}**\n")
        fp.write(f"- Total de repositorios com achados: **{len(repo_summary)}**\n\n")

        sev_counts = Counter(f.severity for f in findings)
        fp.write("## Distribuicao por severidade\n\n")
        fp.write(f"- High: {sev_counts['high']}\n")
        fp.write(f"- Medium: {sev_counts['medium']}\n")
        fp.write(f"- Low: {sev_counts['low']}\n\n")

        fp.write("## Regras\n\n")
        fp.write("- `numeric_type`: CNPJ definido em tipo numerico.\n")
        fp.write("- `numeric_parse`: CNPJ convertido para numero.\n")
        fp.write("- `digits_only_strict`/`digits_only_hint`: validacoes estritas numericas.\n")
        fp.write("- `string_model`: CNPJ em tipo textual (informativo).\n")
        fp.write("- `cnpj_reference`: referencia generica a CNPJ.\n\n")

        fp.write("## Top repositorios por risco\n\n")
        fp.write("| repositorio | severidade_max | high | medium | low | total_achados |\n")
        fp.write("|---|---:|---:|---:|---:|---:|\n")
        for repo, max_sev, h, m, l, total in repo_summary[:300]:
            fp.write(f"| `{repo}` | {max_sev} | {h} | {m} | {l} | {total} |\n")


def parse_args():
    parser = argparse.ArgumentParser(description="Lula Checker IPP 2026 - detector de risco para CNPJ alfanumerico")
    parser.add_argument("--base-dir", default="gitlab_projects_2026-02-11", help="Diretorio base com os repositorios clonados")
    parser.add_argument("--output-dir", default="lula_checker_ipp_2026/output", help="Diretorio de saida dos relatorios")
    parser.add_argument("--include-migracao-ensemble", action="store_true", help="Inclui repos do grupo migracao-ensemble")
    return parser.parse_args()


def main():
    args = parse_args()
    base_dir = Path(args.base_dir)
    output_dir = Path(args.output_dir)

    if not base_dir.exists() or not base_dir.is_dir():
        raise SystemExit(f"Base dir nao encontrada: {base_dir}")

    findings = analyze(base_dir, include_migracao_ensemble=args.include_migracao_ensemble)
    write_outputs(findings, output_dir, base_dir, args.include_migracao_ensemble)

    print(f"Analise concluida. Achados: {len(findings)}")
    print(f"Relatorios em: {output_dir.resolve()}")


if __name__ == "__main__":
    main()
