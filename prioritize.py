#!/usr/bin/env python3
import argparse
import csv
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Tuple


@dataclass(frozen=True)
class Finding:
    repository: str
    file_path: str
    line: int
    severity: str
    rule_id: str
    message: str
    snippet: str


SEV_ORDER = {"high": 3, "medium": 2, "low": 1}


def load_findings(path: Path) -> List[Finding]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    out: List[Finding] = []
    for x in raw:
        out.append(
            Finding(
                repository=x["repository"],
                file_path=x["file_path"],
                line=int(x["line"]),
                severity=x["severity"],
                rule_id=x["rule_id"],
                message=x["message"],
                snippet=x.get("snippet", ""),
            )
        )
    return out


def top_examples(findings: Iterable[Finding], limit: int) -> List[Finding]:
    seen = set()
    out: List[Finding] = []
    for f in sorted(findings, key=lambda z: (z.repository, z.file_path, z.line, z.rule_id)):
        key = (f.repository, f.file_path, f.rule_id, f.snippet.strip())
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
        if len(out) >= limit:
            break
    return out


def write_actionable(findings: List[Finding], out_dir: Path, top_n_repos: int = 50):
    out_dir.mkdir(parents=True, exist_ok=True)

    high = [f for f in findings if f.severity == "high"]
    medium = [f for f in findings if f.severity == "medium"]

    # repo -> counts + top files per rule
    by_repo: Dict[str, List[Finding]] = defaultdict(list)
    for f in findings:
        by_repo[f.repository].append(f)

    repo_rows: List[Tuple[str, str, int, int, int, int]] = []
    for repo, fs in by_repo.items():
        c = Counter(x.severity for x in fs)
        max_sev = max(fs, key=lambda x: SEV_ORDER[x.severity]).severity
        repo_rows.append((repo, max_sev, c["high"], c["medium"], c["low"], len(fs)))
    repo_rows.sort(key=lambda r: (-SEV_ORDER[r[1]], -r[2], -r[3], r[0]))

    # Outputs
    actionable_md = out_dir / "actionable.md"
    high_csv = out_dir / "high_findings.csv"
    repo_csv = out_dir / "repo_risk.csv"
    rule_csv = out_dir / "rule_counts.csv"

    # repo_risk.csv
    with repo_csv.open("w", newline="", encoding="utf-8") as fp:
        w = csv.writer(fp, delimiter=";")
        w.writerow(["repository", "max_severity", "high", "medium", "low", "total_findings"])
        for row in repo_rows:
            w.writerow(list(row))

    # rule_counts.csv
    rule_counts = Counter(f.rule_id for f in findings if f.severity in ("high", "medium"))
    with rule_csv.open("w", newline="", encoding="utf-8") as fp:
        w = csv.writer(fp, delimiter=";")
        w.writerow(["rule_id", "count_high_medium"])
        for rule_id, count in rule_counts.most_common():
            w.writerow([rule_id, count])

    # high_findings.csv (dedup snippet+location a bit)
    with high_csv.open("w", newline="", encoding="utf-8") as fp:
        w = csv.writer(fp, delimiter=";")
        w.writerow(["repository", "file_path", "line", "rule_id", "message", "snippet"])
        for f in sorted(high, key=lambda z: (z.repository, z.file_path, z.line, z.rule_id)):
            w.writerow([f.repository, f.file_path, f.line, f.rule_id, f.message, f.snippet])

    # actionable.md
    with actionable_md.open("w", encoding="utf-8") as fp:
        fp.write("# Lula Checker IPP 2026 - Actionable Report\n\n")
        fp.write(f"- Generated at: {datetime.now().isoformat(timespec='seconds')}\n")
        fp.write(f"- High findings: {len(high)}\n")
        fp.write(f"- Medium findings: {len(medium)}\n\n")

        fp.write("## What To Fix First\n\n")
        fp.write("Priority order:\n")
        fp.write("1. `numeric_type` and `numeric_parse` (hard break with alphanumeric CNPJ)\n")
        fp.write("1. `digits_only_strict` (validations that reject letters)\n")
        fp.write("1. `digits_only_hint` (likely needs adjustment)\n\n")

        fp.write("## Top Repositories By Risk\n\n")
        fp.write("| repository | max_severity | high | medium | low | total |\n")
        fp.write("|---|---:|---:|---:|---:|---:|\n")
        for repo, max_sev, h, m, l, total in repo_rows[:top_n_repos]:
            fp.write(f"| `{repo}` | {max_sev} | {h} | {m} | {l} | {total} |\n")
        fp.write("\n")

        fp.write("## High Findings: Examples (Deduplicated)\n\n")
        by_rule: Dict[str, List[Finding]] = defaultdict(list)
        for f in high:
            by_rule[f.rule_id].append(f)

        for rule_id, fs in sorted(by_rule.items(), key=lambda kv: (-len(kv[1]), kv[0])):
            fp.write(f"### {rule_id} ({len(fs)})\n\n")
            examples = top_examples(fs, limit=20)
            for e in examples:
                fp.write(f"- `{e.repository}` `{e.file_path}:{e.line}`\n")
                fp.write(f"  {e.snippet}\n")
            fp.write("\n")

        unused_csv = out_dir / "unused_cnpj_symbols.csv"
        if unused_csv.exists():
            fp.write("## Unused CNPJ Symbols (Heuristic)\n\n")
            fp.write("These are methods/functions/classes with `cnpj` in the name that appear to be defined but never referenced elsewhere in the same repo.\n")
            fp.write(f"- CSV: `{unused_csv}`\n\n")


def parse_args():
    p = argparse.ArgumentParser(description="Generate actionable/prioritized outputs from Lula Checker findings.json")
    p.add_argument("--findings-json", default="lula_checker_ipp_2026/output/findings.json")
    p.add_argument("--out-dir", default="lula_checker_ipp_2026/output")
    p.add_argument("--top-repos", type=int, default=50)
    return p.parse_args()


def main():
    args = parse_args()
    findings = load_findings(Path(args.findings_json))
    write_actionable(findings, Path(args.out_dir), top_n_repos=args.top_repos)
    print(f"Actionable outputs written to: {Path(args.out_dir).resolve()}")


if __name__ == "__main__":
    main()
