#!/usr/bin/env python3
import argparse
import csv
import json
import re
import subprocess
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple


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


@dataclass(frozen=True)
class SymbolDef:
    repository: str
    file_path: str
    line: int
    language: str
    symbol: str
    snippet: str


@dataclass(frozen=True)
class SymbolUsage:
    repository: str
    file_path: str
    line: int
    symbol: str
    snippet: str


DEF_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("python", re.compile(r"^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.IGNORECASE)),
    ("python", re.compile(r"^\s*class\s+([A-Za-z_][A-Za-z0-9_]*)\b", re.IGNORECASE)),
    ("js_ts", re.compile(r"^\s*(?:export\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(", re.IGNORECASE)),
    ("js_ts", re.compile(r"^\s*(?:export\s+)?const\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?\(", re.IGNORECASE)),
    ("js_ts", re.compile(r"^\s*(?:export\s+)?const\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>", re.IGNORECASE)),
    ("java", re.compile(r"^\s*(?:public|private|protected)?\s*(?:static\s+)?[\w<>\[\],.?\s]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.IGNORECASE)),
    ("kotlin", re.compile(r"^\s*fun\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.IGNORECASE)),
    ("csharp", re.compile(r"^\s*(?:public|private|protected|internal)?\s*(?:static\s+)?[\w<>\[\],.?\s]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.IGNORECASE)),
    ("sql", re.compile(r"^\s*CREATE\s+(?:OR\s+REPLACE\s+)?(?:FUNCTION|PROCEDURE)\s+([A-Za-z_][A-Za-z0-9_\.]*)", re.IGNORECASE)),
]


def run_rg_json(pattern: str, base_dir: Path, *, ignore_case: bool = True, fixed: bool = False) -> Iterable[dict]:
    cmd = ["rg", "--json", "-n", "--hidden", "--follow"]
    if ignore_case:
        cmd.append("-i")
    if fixed:
        cmd.append("-F")
    cmd.extend([pattern, str(base_dir)])
    for g in EXCLUDE_GLOBS:
        cmd.extend(["-g", g])

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert proc.stdout is not None
    for line in proc.stdout:
        line = line.rstrip("\n")
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue

    stderr = proc.stderr.read() if proc.stderr else ""
    code = proc.wait()
    if code not in (0, 1):
        raise RuntimeError(f"rg falhou (code={code}): {stderr.strip()}")


def discover_repositories(base_dir: Path) -> Set[Path]:
    repos: Set[Path] = set()
    for git_dir in base_dir.rglob(".git"):
        if git_dir.is_dir():
            repos.add(git_dir.parent.resolve())
    return repos


def find_repo_for_file(file_path: Path, base_dir: Path, repos: Set[Path], cache: Dict[Path, Optional[Path]]) -> Optional[Path]:
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


def looks_like_cnpj_symbol(name: str) -> bool:
    # Require 'cnpj' in the symbol name. This avoids tons of false positives where
    # a method has a cnpj parameter but the method itself is unrelated.
    return "cnpj" in name.lower()


def extract_symbol_from_line(line: str) -> Optional[Tuple[str, str]]:
    # Returns (language, symbol)
    if "cnpj" not in line.lower():
        return None
    for lang, rx in DEF_PATTERNS:
        m = rx.match(line)
        if not m:
            continue
        sym = m.group(1)
        if looks_like_cnpj_symbol(sym):
            return (lang, sym)
    return None


def collect_cnpj_defs(base_dir: Path, include_migracao_ensemble: bool) -> List[SymbolDef]:
    repos = discover_repositories(base_dir)
    repo_cache: Dict[Path, Optional[Path]] = {}
    out: List[SymbolDef] = []

    # Narrow search: only lines that contain 'cnpj' AND look like a def-ish line.
    for payload in run_rg_json(r"cnpj", base_dir, ignore_case=True, fixed=False):
        if payload.get("type") != "match":
            continue
        data = payload.get("data", {})
        path_text = data.get("path", {}).get("text")
        line_number = data.get("line_number")
        line_text = data.get("lines", {}).get("text", "").rstrip("\n")
        if not path_text or not line_number or not line_text:
            continue

        sym_info = extract_symbol_from_line(line_text)
        if not sym_info:
            continue
        lang, sym = sym_info

        path = Path(path_text)
        repo_path = find_repo_for_file(path, base_dir, repos, repo_cache)
        if not repo_path:
            continue

        repo_rel = str(repo_path.relative_to(base_dir.resolve()))
        if not include_migracao_ensemble and repo_rel.startswith("migracao-ensemble/"):
            continue

        out.append(
            SymbolDef(
                repository=repo_rel,
                file_path=str(path.resolve().relative_to(base_dir.resolve())),
                line=int(line_number),
                language=lang,
                symbol=sym,
                snippet=line_text.strip(),
            )
        )

    # Dedup by repo+file+line+symbol
    seen = set()
    dedup: List[SymbolDef] = []
    for d in out:
        k = (d.repository, d.file_path, d.line, d.symbol)
        if k in seen:
            continue
        seen.add(k)
        dedup.append(d)
    return dedup


def find_usages_for_symbol(base_dir: Path, repo_rel: str, symbol: str) -> List[SymbolUsage]:
    repo_dir = base_dir.resolve() / repo_rel
    # Use fixed-string search for reliability/performance.
    # This can overcount (substrings), but is good enough to decide if something is
    # referenced outside its definition site.
    pattern = symbol
    usages: List[SymbolUsage] = []
    for payload in run_rg_json(pattern, repo_dir, ignore_case=False, fixed=True):
        if payload.get("type") != "match":
            continue
        data = payload.get("data", {})
        path_text = data.get("path", {}).get("text")
        line_number = data.get("line_number")
        line_text = data.get("lines", {}).get("text", "").rstrip("\n")
        if not path_text or not line_number:
            continue
        path = Path(path_text)
        try:
            rel = str(path.resolve().relative_to(base_dir.resolve()))
        except ValueError:
            rel = str(path)
        usages.append(
            SymbolUsage(
                repository=repo_rel,
                file_path=rel,
                line=int(line_number),
                symbol=symbol,
                snippet=(line_text or "").strip(),
            )
        )
    return usages


def main():
    ap = argparse.ArgumentParser(description="Detect unused CNPJ-related symbols (heuristic, no AI)")
    ap.add_argument("--base-dir", default="gitlab_projects_2026-02-11")
    ap.add_argument("--out-dir", default="lula_checker_ipp_2026/output")
    ap.add_argument("--include-migracao-ensemble", action="store_true")
    ap.add_argument("--max-usages-scan", type=int, default=20000, help="Safety cap (not currently used, placeholder)")
    args = ap.parse_args()

    base_dir = Path(args.base_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    defs = collect_cnpj_defs(base_dir, include_migracao_ensemble=args.include_migracao_ensemble)

    # Group defs by repo/symbol; we only care if symbol appears only in the def line(s).
    by_repo_sym: Dict[Tuple[str, str], List[SymbolDef]] = defaultdict(list)
    for d in defs:
        by_repo_sym[(d.repository, d.symbol)].append(d)

    unused_rows = []
    for (repo, sym), def_list in sorted(by_repo_sym.items(), key=lambda x: (x[0][0], x[0][1])):
        usages = find_usages_for_symbol(base_dir, repo, sym)
        # Consider it \"used\" if there is any usage outside the def line(s)
        def_locs = {(d.file_path, d.line) for d in def_list}
        external = [u for u in usages if (u.file_path, u.line) not in def_locs]
        if not external:
            # \"Unused\" heuristic: the only hits are the definitions themselves (or none, but none shouldn't happen).
            # Capture one representative def snippet.
            d0 = sorted(def_list, key=lambda d: (d.file_path, d.line))[0]
            unused_rows.append(
                {
                    "repository": repo,
                    "symbol": sym,
                    "language": d0.language,
                    "def_file": d0.file_path,
                    "def_line": d0.line,
                    "def_snippet": d0.snippet,
                    "total_occurrences_in_repo": len(usages),
                }
            )

    out_csv = out_dir / "unused_cnpj_symbols.csv"
    with out_csv.open("w", newline="", encoding="utf-8") as fp:
        w = csv.writer(fp, delimiter=";")
        w.writerow(
            [
                "repository",
                "symbol",
                "language",
                "def_file",
                "def_line",
                "total_occurrences_in_repo",
                "def_snippet",
            ]
        )
        for r in unused_rows:
            w.writerow(
                [
                    r["repository"],
                    r["symbol"],
                    r["language"],
                    r["def_file"],
                    r["def_line"],
                    r["total_occurrences_in_repo"],
                    r["def_snippet"],
                ]
            )

    print(f"Defs encontradas: {len(defs)}")
    print(f"Simbolos CNPJ possivelmente nao usados: {len(unused_rows)}")
    print(f"CSV: {out_csv.resolve()}")


if __name__ == "__main__":
    main()
