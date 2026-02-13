#!/usr/bin/env python3
import argparse
import csv
import json
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path


NUMERIC_WORDS = r"(?:long|Long|int|Integer|double|Double|float|Float|BigDecimal|BigInteger|bigint|numeric|decimal|number|NUMBER|NUMERIC|DECIMAL|BIGINT|INT|INTEGER)"


def is_noise_path(path: str) -> bool:
    low = path.lower()
    return (
        ".tfstate" in low
        or low.endswith(".min.js")
        or "/target/" in low
        or "/build/" in low
        or "/dist/" in low
    )


def certainty_break(f: dict) -> bool:
    path = f.get("file_path", "")
    snippet = f.get("snippet", "")
    rule_id = f.get("rule_id", "")

    if is_noise_path(path):
        return False

    # Strong certainty: explicit numeric parse/cast involving cnpj.
    if rule_id == "numeric_parse":
        if re.search(r"(parseInt|parseLong|parseDouble|parseFloat|BigDecimal\s*\(|BigInteger\s*\(|CAST\s*\()", snippet, re.IGNORECASE):
            return True
        return False

    if rule_id != "numeric_type":
        return False

    # Strong certainty patterns for numeric modeling.
    strong_patterns = [
        rf"\b[a-zA-Z_]*cnpj[a-zA-Z0-9_]*\b\s*[:=]\s*{NUMERIC_WORDS}\b",  # TS/JS typed/object style
        rf"\b{NUMERIC_WORDS}\b\s+[a-zA-Z_]*cnpj[a-zA-Z0-9_]*\b",  # Java/C#/etc field/param
        rf"\b[a-zA-Z_]*cnpj[a-zA-Z0-9_]*\b.{0,30}\b(?:BIGINT|INT|INTEGER|NUMBER|NUMERIC|DECIMAL)\b",  # SQL-ish
        r"\bString\.format\(\"%014d\"",
        r"\bnew\s+Long\s*\(\s*[a-zA-Z_]*cnpj",
    ]
    for p in strong_patterns:
        if re.search(p, snippet):
            return True
    return False


def main():
    ap = argparse.ArgumentParser(description="Generate final lists: certain break vs possible break")
    ap.add_argument("--findings-json", default="lula_checker_ipp_2026/output/findings.json")
    ap.add_argument("--unused-csv", default="lula_checker_ipp_2026/output/unused_cnpj_symbols.csv")
    ap.add_argument("--out-dir", default="lula_checker_ipp_2026/output")
    args = ap.parse_args()

    findings = json.loads(Path(args.findings_json).read_text(encoding="utf-8"))
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Load unused definition locations to avoid dead-code/lixo cases.
    unused_locs = set()
    unused_path = Path(args.unused_csv)
    if unused_path.exists():
        with unused_path.open(encoding="utf-8") as fp:
            reader = csv.DictReader(fp, delimiter=";")
            for row in reader:
                try:
                    unused_locs.add((row["def_file"], int(row["def_line"])))
                except Exception:
                    continue

    base = [
        f
        for f in findings
        if f.get("severity") in ("high", "medium")
        and f.get("rule_id") in ("numeric_type", "numeric_parse", "digits_only_strict", "digits_only_hint")
    ]

    # Remove dead-symbol definition hits.
    base = [f for f in base if (f.get("file_path"), int(f.get("line", 0))) not in unused_locs]

    certain = [f for f in base if certainty_break(f)]
    possible = [f for f in base if not certainty_break(f)]

    # Dedup rows
    def dedup(rows):
        seen = set()
        out = []
        for r in rows:
            k = (r["repository"], r["file_path"], int(r["line"]), r["rule_id"], r.get("snippet", ""))
            if k in seen:
                continue
            seen.add(k)
            out.append(r)
        return out

    certain = dedup(certain)
    possible = dedup(possible)

    # Sort by repository/file/line
    certain.sort(key=lambda r: (r["repository"], r["file_path"], int(r["line"])))
    possible.sort(key=lambda r: (r["repository"], r["file_path"], int(r["line"])))

    certain_csv = out_dir / "lista_final_certeza_quebra.csv"
    possible_csv = out_dir / "lista_final_possivel_quebra.csv"
    summary_md = out_dir / "lista_final_resumo.md"

    def write_csv(path: Path, rows):
        with path.open("w", newline="", encoding="utf-8") as fp:
            w = csv.writer(fp, delimiter=";")
            w.writerow(["repository", "file_path", "line", "severity", "rule_id", "message", "snippet"])
            for r in rows:
                w.writerow([
                    r.get("repository"),
                    r.get("file_path"),
                    r.get("line"),
                    r.get("severity"),
                    r.get("rule_id"),
                    r.get("message"),
                    r.get("snippet", ""),
                ])

    write_csv(certain_csv, certain)
    write_csv(possible_csv, possible)

    # Markdown summary
    by_repo_certain = defaultdict(int)
    by_repo_possible = defaultdict(int)
    for r in certain:
        by_repo_certain[r["repository"]] += 1
    for r in possible:
        by_repo_possible[r["repository"]] += 1

    top_certain = sorted(by_repo_certain.items(), key=lambda kv: (-kv[1], kv[0]))[:40]
    top_possible = sorted(by_repo_possible.items(), key=lambda kv: (-kv[1], kv[0]))[:40]

    with summary_md.open("w", encoding="utf-8") as fp:
        fp.write("# Lista Final - CNPJ Alfanumerico\n\n")
        fp.write(f"- Gerado em: {datetime.now().isoformat(timespec='seconds')}\n")
        fp.write(f"- Certeza que quebra: **{len(certain)}**\n")
        fp.write(f"- Possivel quebrar: **{len(possible)}**\n\n")

        fp.write("## Certeza Que Quebra (top repos)\n\n")
        fp.write("| repositorio | qtd |\n")
        fp.write("|---|---:|\n")
        for repo, qtd in top_certain:
            fp.write(f"| `{repo}` | {qtd} |\n")
        fp.write("\n")

        fp.write("## Possivel Quebrar (top repos)\n\n")
        fp.write("| repositorio | qtd |\n")
        fp.write("|---|---:|\n")
        for repo, qtd in top_possible:
            fp.write(f"| `{repo}` | {qtd} |\n")

    print(f"Certeza quebra: {len(certain)}")
    print(f"Possivel quebrar: {len(possible)}")
    print(f"CSV certeza: {certain_csv.resolve()}")
    print(f"CSV possivel: {possible_csv.resolve()}")
    print(f"Resumo: {summary_md.resolve()}")


if __name__ == "__main__":
    main()

