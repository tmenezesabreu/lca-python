#!/usr/bin/env python3
import argparse
import csv
import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path


BREAKING_RULES = {"numeric_type", "numeric_parse", "digits_only_strict", "digits_only_hint"}
BREAKING_SEVERITIES = {"high", "medium"}


def load_findings(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def load_unused_def_locs(path: Path):
    locs = set()
    if not path.exists():
        return locs
    with path.open(encoding="utf-8") as fp:
        reader = csv.DictReader(fp, delimiter=";")
        for row in reader:
            try:
                locs.add((row["def_file"], int(row["def_line"])))
            except Exception:
                continue
    return locs


def main():
    ap = argparse.ArgumentParser(description="Create focused breakage report (only in-use break risks)")
    ap.add_argument("--findings-json", default="lula_checker_ipp_2026/output/findings.json")
    ap.add_argument("--unused-csv", default="lula_checker_ipp_2026/output/unused_cnpj_symbols.csv")
    ap.add_argument("--out-dir", default="lula_checker_ipp_2026/output")
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    findings = load_findings(Path(args.findings_json))
    unused_locs = load_unused_def_locs(Path(args.unused_csv))

    focused = []
    for f in findings:
        if f.get("severity") not in BREAKING_SEVERITIES:
            continue
        if f.get("rule_id") not in BREAKING_RULES:
            continue
        file_path = f.get("file_path")
        line = int(f.get("line", 0))
        if (file_path, line) in unused_locs:
            # Explicitly skip break findings that are in a CNPJ symbol
            # flagged as unused/dead-code candidate.
            continue
        focused.append(f)

    focused_json = out_dir / "focused_breakage_findings.json"
    focused_csv = out_dir / "focused_breakage_findings.csv"
    focused_md = out_dir / "focused_breakage_summary.md"

    focused_json.write_text(json.dumps(focused, ensure_ascii=False, indent=2), encoding="utf-8")

    with focused_csv.open("w", newline="", encoding="utf-8") as fp:
        w = csv.writer(fp, delimiter=";")
        w.writerow(["repository", "file_path", "line", "severity", "rule_id", "message", "snippet"])
        for f in focused:
            w.writerow(
                [
                    f.get("repository"),
                    f.get("file_path"),
                    f.get("line"),
                    f.get("severity"),
                    f.get("rule_id"),
                    f.get("message"),
                    f.get("snippet", ""),
                ]
            )

    by_repo = defaultdict(list)
    for f in focused:
        by_repo[f["repository"]].append(f)

    sev_counts = Counter(f["severity"] for f in focused)
    rule_counts = Counter(f["rule_id"] for f in focused)

    ranking = []
    for repo, fs in by_repo.items():
        c = Counter(x["severity"] for x in fs)
        ranking.append((repo, c["high"], c["medium"], len(fs)))
    ranking.sort(key=lambda r: (-r[1], -r[2], r[0]))

    with focused_md.open("w", encoding="utf-8") as fp:
        fp.write("# Lula Checker IPP 2026 - Focused Breakage Report\n\n")
        fp.write(f"- Generated at: {datetime.now().isoformat(timespec='seconds')}\n")
        fp.write(f"- Source findings: `{args.findings_json}`\n")
        fp.write(f"- Unused symbols filter: `{args.unused_csv}`\n")
        fp.write(f"- Included rules: {', '.join(sorted(BREAKING_RULES))}\n")
        fp.write(f"- Included severities: {', '.join(sorted(BREAKING_SEVERITIES))}\n\n")

        fp.write("## Totals\n\n")
        fp.write(f"- Focused findings: **{len(focused)}**\n")
        fp.write(f"- High: {sev_counts['high']}\n")
        fp.write(f"- Medium: {sev_counts['medium']}\n")
        fp.write(f"- Repositories: {len(by_repo)}\n\n")

        fp.write("## Rule Distribution\n\n")
        for rule, count in rule_counts.most_common():
            fp.write(f"- `{rule}`: {count}\n")
        fp.write("\n")

        fp.write("## Top Repositories To Fix First\n\n")
        fp.write("| repository | high | medium | total |\n")
        fp.write("|---|---:|---:|---:|\n")
        for repo, high, medium, total in ranking[:150]:
            fp.write(f"| `{repo}` | {high} | {medium} | {total} |\n")

    print(f"Focused findings: {len(focused)}")
    print(f"Focused report: {focused_md.resolve()}")


if __name__ == "__main__":
    main()

