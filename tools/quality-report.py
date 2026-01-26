#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright 2025 - 2026 gematik GmbH
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# *******
#
# For additional notes and disclaimer from gematik and in case of changes by gematik,
# find details in the "Readme" file.

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from shutil import which
from typing import Any


ROOT = Path(__file__).resolve().parent.parent

TEST_ATTR_RE = re.compile(r"^\s*#\[\s*(test|tokio::test|rstest)\b")
COMMENT_RE = re.compile(r"^\s*(//|///)")

# "One-liners with logic" (comparisons, short-circuit, bit ops, iterator logic).
LOGIC_METHOD_CALLS = (".map(", ".filter(", ".find(", ".any(", ".all(", ".fold(", ".map_err(", ".ok_or", ".ok_or_else(")
# Only treat `<`/`>` as comparisons when surrounded by whitespace to avoid false positives from generics (`Result<T>`),
# bounds (`From<T>`), and `=>` in match arms.
LOGIC_OP_RE = re.compile(r"(==|!=|<=|>=|&&|\|\||<<|>>|\s[<>]\s)")
BITWISE_OP_RE = re.compile(r"(\s\|\s|\s&\s|\s\^\s|&=|\|=|\^=)")


@dataclass(frozen=True)
class Fn:
    file: str
    name: str
    start: int
    end: int
    cyclo: int
    ploc: int


@dataclass(frozen=True)
class Risk:
    file: str
    name: str
    start: int
    end: int
    cyclo: int
    ploc: int
    branches_uncovered: int
    logic_lines_uncovered: int
    score: int
    uncovered_branch_spans: tuple[dict[str, Any], ...]
    uncovered_logic_lines: tuple[dict[str, Any], ...]


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="quality-report")
    p.add_argument("--coverage-json", default="target/llvm-cov.json", help="Stable line coverage JSON.")
    p.add_argument(
        "--coverage-branch-json",
        default="target/llvm-cov.branch.json",
        help="Nightly branch coverage JSON (cargo +nightly cov-json-branch).",
    )
    p.add_argument("--include-roots", default="core-modules", help="Comma-separated roots to analyze.")
    p.add_argument(
        "--min-cyclo-for-branches",
        type=int,
        default=2,
        help="Only treat uncovered branch edges as risk for functions with cyclomatic complexity >= this.",
    )
    p.add_argument("--out-md", default="target/quality-report.md")
    p.add_argument("--out-json", default="target/quality-report.json")
    p.add_argument("--out-tasks", default="target/quality-tasks.jsonl", help="AI-consumable tasks (JSONL).")
    p.add_argument("--fail-under", action="store_true", help="Exit with code 1 if any risks are found.")
    return p.parse_args(argv)


def rel_to_root(path_str: str) -> str:
    p = Path(path_str)
    try:
        return str(p.relative_to(ROOT))
    except ValueError:
        return str(p)


def load_cov(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    obj = json.loads(path.read_text(encoding="utf-8"))
    data = (obj.get("data") or [{}])[0]
    out: dict[str, dict[str, Any]] = {}
    for f in data.get("files") or []:
        filename = f.get("filename")
        if filename:
            out[rel_to_root(filename)] = {"segments": f.get("segments") or [], "branches": f.get("branches") or []}
    return out


def line_hits(segments: list[list[Any]]) -> dict[int, int]:
    hits: dict[int, int] = {}
    for seg in segments:
        # [line, col, count, hasCount, ...]
        if len(seg) >= 4 and bool(seg[3]):
            line = int(seg[0])
            hits[line] = max(hits.get(line, 0), int(seg[2]))
    return hits


def uncovered_branch_edges(branches: list[list[Any]], start: int, end: int) -> tuple[int, list[dict[str, Any]]]:
    # [line, col, endLine, endCol, countA, countB, ...]
    # Important: generic functions can appear multiple times (monomorphizations) with the same source span.
    # For risk assessment we treat a branch edge as covered if *any* instantiation covers it, so we aggregate
    # by source span and take the max counts.
    by_span: dict[tuple[int, int, int, int, int], tuple[int, int]] = {}
    for br in branches:
        if len(br) < 6:
            continue
        line = int(br[0])
        if not (start <= line <= end):
            continue
        col = int(br[1]) if len(br) > 1 else 0
        end_line = int(br[2]) if len(br) > 2 else line
        end_col = int(br[3]) if len(br) > 3 else col
        kind = int(br[8]) if len(br) > 8 else -1
        key = (line, col, end_line, end_col, kind)

        count_a = int(br[4])
        count_b = int(br[5])
        prev = by_span.get(key)
        if prev is None:
            by_span[key] = (count_a, count_b)
        else:
            by_span[key] = (max(prev[0], count_a), max(prev[1], count_b))

    missing = 0
    uncovered: list[dict[str, Any]] = []
    for (line, col, end_line, end_col, kind), (count_a, count_b) in by_span.items():
        missing_a = count_a == 0
        missing_b = count_b == 0
        if count_a == 0:
            missing += 1
        if count_b == 0:
            missing += 1
        if missing_a or missing_b:
            uncovered.append(
                {
                    "line": line,
                    "col": col,
                    "end_line": end_line,
                    "end_col": end_col,
                    "kind": kind,
                    "count_a": count_a,
                    "count_b": count_b,
                    "missing_a": missing_a,
                    "missing_b": missing_b,
                }
            )
    uncovered.sort(key=lambda d: (d["line"], d["col"], d["end_line"], d["end_col"], d["kind"]))
    return missing, uncovered


def is_logic_line(line: str) -> bool:
    s = line.strip()
    if not s or COMMENT_RE.match(s):
        return False
    if any(call in s for call in LOGIC_METHOD_CALLS):
        return True
    return bool(LOGIC_OP_RE.search(s) or BITWISE_OP_RE.search(s))


def is_test_context(lines: list[str], start_line: int) -> bool:
    start_idx = max(0, start_line - 1)
    for j in range(max(0, start_idx - 8), start_idx):
        l = lines[j].strip()
        if TEST_ATTR_RE.match(l):
            return True
        if "cfg(test" in l:
            return True
        if re.match(r"^\s*mod\s+tests\b", l):
            return True
    return False


def is_trivial_accessor(fn: Fn, fn_lines: list[str]) -> bool:
    if fn.cyclo != 1 or fn.ploc > 3:
        return False
    # Closures usually imply non-trivial logic.
    if any("|" in l for l in fn_lines):
        return False
    joined = " ".join(l.strip() for l in fn_lines if l.strip() and not COMMENT_RE.match(l.strip()))
    joined = re.sub(r"\s+", " ", joined).strip()
    if not joined:
        return True
    if "(" in joined:
        return False
    if is_logic_line(joined):
        return False
    if re.search(r"\bself\.[A-Za-z_]\w*\s*=", joined):
        return True
    if re.search(r"\bself\.[A-Za-z_]\w*\b", joined):
        return True
    return False


def run_rca(roots: list[str]) -> list[Fn]:
    if not which("rust-code-analysis-cli"):
        raise RuntimeError("rust-code-analysis-cli not found in PATH")
    with tempfile.TemporaryDirectory(prefix="rca-") as tmp:
        out_dir = Path(tmp)
        args = ["rust-code-analysis-cli", "--metrics", "-O", "json"]
        for root in roots:
            args += ["-p", root, "-I", "**/*.rs", "-X", "**/target/**"]
        args += ["-o", str(out_dir)]
        subprocess.run(args, check=True, cwd=ROOT, stdout=subprocess.DEVNULL)

        fns: list[Fn] = []
        stack: list[tuple[dict[str, Any], list[str], str]] = []
        for p in out_dir.rglob("*.rs.json"):
            file_path = str(p.relative_to(out_dir)).removesuffix(".json")
            stack.append((json.loads(p.read_text(encoding="utf-8")), [], file_path))
        while stack:
            node, parents, file_path = stack.pop()
            kind = node.get("kind")
            name = node.get("name") or ""
            next_parents = parents
            if kind in ("impl", "trait", "struct", "enum", "mod", "unit") and name:
                next_parents = parents + [name]
            if kind == "function":
                metrics = node.get("metrics") or {}
                cyclo = int(float((metrics.get("cyclomatic") or {}).get("sum") or 0.0))
                ploc = int(float((metrics.get("loc") or {}).get("ploc") or 0.0))
                start = int(node.get("start_line") or 0)
                end = int(node.get("end_line") or start)
                qname = "::".join([p for p in next_parents if p] + ([name] if name else [])) or name
                fns.append(Fn(file=file_path, name=qname, start=start, end=end, cyclo=cyclo, ploc=ploc))
            for child in node.get("spaces") or []:
                stack.append((child, next_parents, file_path))
        return fns


def compute_risks(
    fns: list[Fn],
    cov_line: dict[str, dict[str, Any]],
    cov_branch: dict[str, dict[str, Any]],
    include_roots: list[str],
    min_cyclo_for_branches: int,
) -> list[Risk]:
    include = tuple(r.rstrip("/") + "/" for r in include_roots)
    source_cache: dict[str, list[str]] = {}
    risks: list[Risk] = []

    def get_lines(file: str) -> list[str]:
        if file not in source_cache:
            source_cache[file] = (ROOT / file).read_text(encoding="utf-8", errors="replace").splitlines()
        return source_cache[file]

    for fn in fns:
        if not fn.file.startswith(include):
            continue
        normalized = fn.file.replace("\\", "/")
        if "/tests/" in normalized or "/src/bin/" in normalized or normalized.endswith("/src/main.rs"):
            continue
        if "/src/" not in normalized:
            continue

        lines = get_lines(fn.file)
        start = max(1, fn.start)
        end = min(max(start, fn.end), len(lines))
        body = lines[start - 1 : end]

        if is_test_context(lines, start):
            continue
        if is_trivial_accessor(fn, body):
            continue

        hits = line_hits((cov_line.get(fn.file) or {}).get("segments") or [])
        uncovered_logic_lines = [
            {"line": start + i, "text": l.rstrip()}
            for i, l in enumerate(body)
            if is_logic_line(l) and (start + i) in hits and hits[start + i] == 0
        ]
        uncovered_logic = len(uncovered_logic_lines)

        uncovered_branch_spans: list[dict[str, Any]] = []
        uncovered_branches = 0
        if fn.cyclo >= min_cyclo_for_branches:
            uncovered_branches, uncovered_branch_spans = uncovered_branch_edges(
                (cov_branch.get(fn.file) or {}).get("branches") or [], start, end
            )
            for br in uncovered_branch_spans:
                line_no = br["line"]
                if 1 <= line_no <= len(lines):
                    br["text"] = lines[line_no - 1].rstrip()

        score = (10 * uncovered_branches) + (2 * uncovered_logic)
        if score:
            risks.append(
                Risk(
                    file=fn.file,
                    name=fn.name,
                    start=start,
                    end=end,
                    cyclo=fn.cyclo,
                    ploc=fn.ploc,
                    branches_uncovered=uncovered_branches,
                    logic_lines_uncovered=uncovered_logic,
                    score=score,
                    uncovered_branch_spans=tuple(uncovered_branch_spans),
                    uncovered_logic_lines=tuple(uncovered_logic_lines),
                )
            )

    risks.sort(key=lambda r: (-r.score, r.file, r.start, r.name))
    return risks


def crate_from_path(file_path: str) -> Optional[str]:
    # core-modules/<crate>/...
    parts = file_path.split("/")
    if len(parts) >= 2 and parts[0] == "core-modules":
        return parts[1]
    return None


def write_tasks(out_tasks: Path, risks: list[Risk], meta: dict[str, Any]) -> None:
    out_tasks.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    for r in risks:
        crate = crate_from_path(r.file)
        task = {
            "id": f"{r.file}:{r.start}:{r.name}",
            "file": r.file,
            "function": r.name,
            "span": {"start": r.start, "end": r.end},
            "crate": crate,
            "metrics": {"cyclo": r.cyclo, "ploc": r.ploc},
            "risk": {
                "score": r.score,
                "branches_uncovered": r.branches_uncovered,
                "logic_lines_uncovered": r.logic_lines_uncovered,
            },
            "uncovered": {
                "branch_spans": list(r.uncovered_branch_spans),
                "logic_lines": list(r.uncovered_logic_lines),
            },
            "meta": {
                "coverage_json": meta["coverage_json"],
                "coverage_branch_json": meta["coverage_branch_json"],
                "min_cyclo_for_branches": meta["min_cyclo_for_branches"],
            },
            "suggested_commands": ([f"cargo test -p {crate}"] if crate else []),
        }
        lines.append(json.dumps(task, sort_keys=True))
    out_tasks.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def write_reports(out_md: Path, out_json: Path, out_tasks: Path, risks: list[Risk], meta: dict[str, Any]) -> None:
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.parent.mkdir(parents=True, exist_ok=True)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    overall = "ENOUGH" if not risks else "NOT ENOUGH"

    file_scores: dict[str, int] = {}
    file_counts: dict[str, int] = {}
    for r in risks:
        file_scores[r.file] = file_scores.get(r.file, 0) + r.score
        file_counts[r.file] = file_counts.get(r.file, 0) + 1

    md: list[str] = []
    md += ["# Rust unit test risk report", "", f"Generated: `{now}`", ""]
    md += [
        "## Scoring",
        "",
        "This report is *risk-based* and intentionally does not penalize uncovered trivial accessors.",
        "",
        "A function contributes risk when:",
        "- It is production code (not `#[test]` / `cfg(test)`), and",
        "- It is not classified as a trivial getter/setter, and",
        "- Either uncovered branch edges are found (control-flow), or uncovered logic lines are found (one-liners).",
        "",
        "Risk score per function:",
        "",
        "`score = 10 * branches_uncovered + 2 * logic_lines_uncovered`",
        "",
        "Notes:",
        f"- `branches_uncovered` is only counted when cyclomatic complexity is >= `{meta['min_cyclo_for_branches']}`.",
        "- Branch edges are deduplicated by source span and treated as covered if any monomorphization covers them.",
        "- `logic_lines_uncovered` counts uncovered single-line logic (comparisons, bitwise ops, iterator logic, short-circuit).",
        "",
    ]
    md += [
        "## Result",
        "",
        f"- Overall: `{overall}`",
        f"- Risky functions: `{len(risks)}`",
        f"- Tasks (JSONL): `{out_tasks}`",
        "",
    ]
    md += ["## Risky Files (by score)", ""]
    if file_scores:
        md += ["| File | Total score | Risky functions |", "|---|---:|---:|"]
        for file, score in sorted(file_scores.items(), key=lambda kv: (-kv[1], kv[0])):
            md.append(f"| `{file}` | {score} | {file_counts[file]} |")
    else:
        md.append("- (none)")

    md += ["", "## Risks (all)", ""]
    if risks:
        md += [
            "| Location | Function | Cyclo | PLOC | Uncovered branches | Uncovered logic lines | Score |",
            "|---|---|---:|---:|---:|---:|---:|",
        ]
        for r in risks:
            md.append(
                f"| `{r.file}:{r.start}` | `{r.name}` | {r.cyclo} | {r.ploc} | {r.branches_uncovered} | {r.logic_lines_uncovered} | {r.score} |"
            )
    else:
        md.append("- No uncovered branches/logic found in non-trivial production code.")
    out_md.write_text("\n".join(md) + "\n", encoding="utf-8")

    out_json.write_text(
        json.dumps({"meta": meta | {"overall": overall}, "risks": [asdict(r) for r in risks]}, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    write_tasks(out_tasks, risks, meta)


def main(argv: list[str]) -> int:
    a = parse_args(argv)
    roots = [s.strip() for s in a.include_roots.split(",") if s.strip()]

    cov_line = load_cov((ROOT / a.coverage_json).resolve())
    cov_branch = load_cov((ROOT / a.coverage_branch_json).resolve())
    fns = run_rca(roots)
    risks = compute_risks(
        fns=fns,
        cov_line=cov_line,
        cov_branch=cov_branch,
        include_roots=roots,
        min_cyclo_for_branches=a.min_cyclo_for_branches,
    )

    out_md = ROOT / a.out_md
    out_json = ROOT / a.out_json
    out_tasks = ROOT / a.out_tasks
    meta = {
        "coverage_json": str(Path(a.coverage_json)),
        "coverage_branch_json": str(Path(a.coverage_branch_json)),
        "include_roots": roots,
        "min_cyclo_for_branches": a.min_cyclo_for_branches,
    }
    write_reports(out_md, out_json, out_tasks, risks, meta)

    print(f"overall: {'ENOUGH' if not risks else 'NOT ENOUGH'}")
    print(f"report: {out_md}")
    if risks:
        print("top_risks:")
        for r in risks[:10]:
            print(f"- {r.file}:{r.start} {r.name}: branches={r.branches_uncovered} logic_lines={r.logic_lines_uncovered}")

    if a.fail_under and risks:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
