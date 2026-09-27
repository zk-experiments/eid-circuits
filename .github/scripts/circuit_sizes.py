#!/usr/bin/env python3
"""Measure every Noir bin circuit in the workspace, and diff two measurements.

Ported from psonet/pso-zk-circuits (.github/scripts/circuit_sizes.py). Circuit
size is the cost model: ACIR opcode count drives witness generation, and
`circuit_size` (the backend gate count) drives proving time, memory and the
VK. Both move silently, so CI measures them and a PR comment shows the delta.

  collect <workspace> -o sizes.json   compile the workspace, record each bin's sizes
  report <base.json> <head.json>      render the comparison as Markdown
  check <sizes.json>                  fail if a circuit exceeds the memory cap

Differences from the psonet original: circuits are discovered from the root
Nargo.toml `members` (every package with `type = "bin"`) instead of a fixed
list, the workspace is compiled once, and the target is `noir-recursive`:
the step circuits are verified inside the aggregation circuit.
"""

import argparse
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

# Gate counts are the same for every bb target (checked for noir-recursive and
# evm), so one target measures all of them.
TARGET = "noir-recursive"
# Below this, a move is noise from a compiler detail rather than a change
# worth a reviewer's attention.
NOTABLE_PCT = 1.0
# Hard cap on proving memory, so every circuit proves on a phone. Peak memory
# is linear in gates, not in the padded power-of-two size: `bb prove` measured
# 1,985–2,418 bytes per gate (docs/data/prove-times.json), so 2,500 bytes per
# gate leaves a margin. The cap is 2 GiB / 2,500 = 858,993 gates.
MEMORY_CAP_BYTES = 2 * 2**30
BYTES_PER_GATE = 2500
MAX_GATES = MEMORY_CAP_BYTES // BYTES_PER_GATE


def run(cmd, **kw):
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if r.returncode != 0:
        print(f"$ {' '.join(map(str, cmd))}\n{r.stdout}\n{r.stderr}", file=sys.stderr)
        raise SystemExit(f"command failed: {cmd[0]}")
    return r.stdout


def bin_packages(workspace: Path) -> list[str]:
    """Names of the bin packages listed in the workspace's root Nargo.toml."""
    root = tomllib.loads((workspace / "Nargo.toml").read_text())
    names = []
    for member in root.get("workspace", {}).get("members", []):
        pkg = tomllib.loads((workspace / member / "Nargo.toml").read_text())["package"]
        if pkg.get("type") == "bin":
            names.append(pkg["name"])
    return sorted(names)


def collect(workspace: Path, nargo: str, bb: str) -> dict:
    out = {}
    if not (workspace / "Nargo.toml").exists():
        # A base that predates the workspace has nothing to measure.
        return out
    names = bin_packages(workspace)
    if names:
        run([nargo, "compile", "--workspace"], cwd=workspace)
    for module in names:
        artifact = workspace / "target" / f"{module}.json"
        if not artifact.exists():
            raise SystemExit(f"nargo compile produced no {artifact}")
        raw = run([bb, "gates", "-b", str(artifact), "-t", TARGET])
        doc = json.loads(raw)
        fns = doc.get("functions") or []
        if not fns:
            raise SystemExit(f"bb gates returned no functions for {module}: {raw[:200]}")
        out[module] = {
            "opcodes": sum(f["acir_opcodes"] for f in fns),
            "gates": sum(f["circuit_size"] for f in fns),
        }
        print(f"  {module:40} opcodes={out[module]['opcodes']:>9,}  "
              f"gates={out[module]['gates']:>10,}", file=sys.stderr)
    return out


def delta(before: int | None, after: int | None) -> str:
    if before is None or (before == 0 and after):
        return "new"
    if after is None:
        return "removed"
    d = after - before
    if d == 0:
        return "—"
    pct = (d / before * 100) if before else 0.0
    return f"{d:+,} ({pct:+.2f}%)"


def report(base: dict, head: dict, base_ref: str) -> str:
    modules = sorted(set(base) | set(head))
    rows, moved = [], False
    for m in modules:
        b, h = base.get(m), head.get(m)
        bo, ho = (b or {}).get("opcodes"), (h or {}).get("opcodes")
        bg, hg = (b or {}).get("gates"), (h or {}).get("gates")
        if (bo, bg) != (ho, hg):
            moved = True
        rows.append(
            f"| `{m}` | {ho if ho is not None else '—':,} | {delta(bo, ho)} "
            f"| {hg if hg is not None else '—':,} | {delta(bg, hg)} |"
            if isinstance(ho, int) and isinstance(hg, int) else
            f"| `{m}` | — | {delta(bo, ho)} | — | {delta(bg, hg)} |"
        )

    tb = sum(v["gates"] for v in base.values())
    th = sum(v["gates"] for v in head.values())

    out = ["## Circuit size", ""]
    if not moved:
        out += [f"No change against `{base_ref}`.", ""]
    else:
        out += [f"Total gates **{th:,}** against **{tb:,}** on `{base_ref}` "
                f"— {delta(tb, th)}.", ""]
    out += [
        "| Circuit | ACIR opcodes | Δ | Gates | Δ |",
        "|---|---:|---:|---:|---:|",
        *rows,
        "",
        f"<sub>`bb gates -t {TARGET}`, the target the step circuits are proven for. "
        "Gate count drives proving time, memory and the VK; opcodes drive witness "
        "generation.</sub>",
    ]
    return "\n".join(out)


def check(sizes: dict) -> int:
    over = {m: v["gates"] for m, v in sizes.items() if v["gates"] > MAX_GATES}
    for m, g in sorted(over.items()):
        print(f"::error::{m}: {g:,} gates exceeds the {MAX_GATES:,}-gate cap "
              f"(≈{g * BYTES_PER_GATE / 2**30:.2f} GiB against {MEMORY_CAP_BYTES / 2**30:.0f} GiB)")
    top = max(sizes.values(), key=lambda v: v["gates"], default={"gates": 0})["gates"]
    print(f"{len(sizes)} circuits, largest {top:,} gates, cap {MAX_GATES:,}", file=sys.stderr)
    return 1 if over else 0


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("collect")
    c.add_argument("workspace", type=Path)
    c.add_argument("-o", "--output", type=Path, required=True)
    c.add_argument("--nargo", default="nargo")
    c.add_argument("--bb", default="bb")

    r = sub.add_parser("report")
    r.add_argument("base", type=Path)
    r.add_argument("head", type=Path)
    r.add_argument("--base-ref", default="base")

    k = sub.add_parser("check")
    k.add_argument("sizes", type=Path)

    a = ap.parse_args()
    if a.cmd == "collect":
        a.output.write_text(json.dumps(collect(a.workspace, a.nargo, a.bb), indent=2, sort_keys=True))
        print(f"wrote {a.output}", file=sys.stderr)
    elif a.cmd == "check":
        raise SystemExit(check(json.loads(a.sizes.read_text())))
    else:
        print(report(json.loads(a.base.read_text()),
                     json.loads(a.head.read_text()), a.base_ref))


if __name__ == "__main__":
    main()
