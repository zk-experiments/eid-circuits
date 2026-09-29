#!/usr/bin/env python3
"""Measure every Noir bin circuit in the workspace, and diff two measurements.

Ported from psonet/pso-zk-circuits (.github/scripts/circuit_sizes.py). Circuit
size is the cost model: ACIR opcode count drives witness generation, and
`circuit_size` (the backend gate count) drives proving time, memory and the
VK. Both move silently, so CI measures them and a PR comment shows the delta.

  collect <workspace> -o sizes.json   record each bin's sizes (see below)
  verify <committed.json> <measured>  fail if measured entries differ from the committed ones
  report <base.json> <head.json>      render the comparison as Markdown
  check <sizes.json>                  fail if a circuit exceeds the memory cap

Compiling and measuring all ~300 circuits takes over an hour on a CI runner,
so CI never does it. The full set lives in docs/data/circuit-sizes.json,
refreshed locally with

  python3 .github/scripts/circuit_sizes.py collect . \
      --cache docs/data/circuit-sizes.json -o docs/data/circuit-sizes.json

Each entry records a SHA-256 of the circuit's compiled bytecode; with
`--cache`, circuits whose bytecode is unchanged keep their entry and skip
`bb gates`. CI compiles only the executed samples, measures them with the
same cache, and `verify` fails when the committed file is stale.

Differences from the psonet original: circuits are discovered from the root
Nargo.toml `members` (every package with `type = "bin"`) instead of a fixed
list, the workspace is compiled once, and circuits are measured for Chonk
(`bb gates --scheme chonk`, the Mega arithmetisation the folded proof uses).
"""

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

# Circuits are folded with Chonk; UltraHonk can't build databus circuits.
SCHEME = "chonk"
# Below this, a move is noise from a compiler detail rather than a change
# worth a reviewer's attention.
NOTABLE_PCT = 1.0
# Hard cap on proving memory, so every circuit proves on a phone. Peak memory
# is linear in gates, not in the padded power-of-two size: `bb prove` measured
# 1,985–2,418 bytes per gate (UltraHonk, 31 circuits; a folded Chonk document
# peaks at about 2,350 bytes per gate of its largest circuit), so 2,500 bytes per
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


def bytecode_hash(artifact: Path) -> str:
    """SHA-256 of the compiled bytecode (nargo's own `hash` depends on paths)."""
    return hashlib.sha256(json.loads(artifact.read_text())["bytecode"].encode()).hexdigest()


def collect(workspace: Path, nargo: str, bb: str, packages: list[str] | None,
            compile_: bool, cache: dict) -> dict:
    out = {}
    if not (workspace / "Nargo.toml").exists():
        # A base that predates the workspace has nothing to measure.
        return out
    names = packages if packages is not None else bin_packages(workspace)
    if names and compile_:
        if packages is None:
            run([nargo, "compile", "--workspace"], cwd=workspace)
        else:
            for name in names:
                run([nargo, "compile", "--package", name], cwd=workspace)
    for module in names:
        artifact = workspace / "target" / f"{module}.json"
        if not artifact.exists():
            raise SystemExit(f"no compiled {artifact}")
        digest = bytecode_hash(artifact)
        cached = cache.get(module)
        if cached and cached.get("bytecode_sha256") == digest:
            out[module] = cached
            continue
        raw = run([bb, "gates", "--scheme", SCHEME, "-b", str(artifact)])
        doc = json.loads(raw)
        fns = doc.get("functions") or []
        if not fns:
            raise SystemExit(f"bb gates returned no functions for {module}: {raw[:200]}")
        out[module] = {
            "bytecode_sha256": digest,
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
        f"<sub>Committed `docs/data/circuit-sizes.json` (`bb gates --scheme {SCHEME}`). "
        "Gate count drives proving time, memory and the VK; opcodes drive witness "
        "generation.</sub>",
    ]
    return "\n".join(out)


def verify(committed: dict, measured: dict, workspace: Path) -> int:
    """Measured entries must equal the committed ones, and the committed file
    must list exactly the workspace's bin packages."""
    bad = 0
    names = set(bin_packages(workspace))
    for m in sorted(names ^ set(committed)):
        print(f"::error::{m}: {'missing from' if m in names else 'not a package but in'} "
              "docs/data/circuit-sizes.json")
        bad += 1
    for m, v in sorted(measured.items()):
        if committed.get(m) != v:
            print(f"::error::{m}: committed {committed.get(m)} but measured {v}")
            bad += 1
    if bad:
        print("docs/data/circuit-sizes.json is stale; refresh it with `python3 "
              ".github/scripts/circuit_sizes.py collect . --cache "
              "docs/data/circuit-sizes.json -o docs/data/circuit-sizes.json`", file=sys.stderr)
    else:
        print(f"{len(measured)} measured circuits match the committed sizes", file=sys.stderr)
    return 1 if bad else 0


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
    c.add_argument("--packages", type=Path,
                   help="file with one package name per line (default: every bin)")
    c.add_argument("--no-compile", action="store_true",
                   help="use the artifacts already in target/")
    c.add_argument("--cache", type=Path,
                   help="sizes file whose entries are reused when the bytecode is unchanged")

    v = sub.add_parser("verify")
    v.add_argument("committed", type=Path)
    v.add_argument("measured", type=Path)
    v.add_argument("--workspace", type=Path, default=Path("."))

    r = sub.add_parser("report")
    r.add_argument("base", type=Path)
    r.add_argument("head", type=Path)
    r.add_argument("--base-ref", default="base")

    k = sub.add_parser("check")
    k.add_argument("sizes", type=Path)

    a = ap.parse_args()
    if a.cmd == "collect":
        packages = a.packages.read_text().split() if a.packages else None
        cache = json.loads(a.cache.read_text()) if a.cache and a.cache.exists() else {}
        sizes = collect(a.workspace, a.nargo, a.bb, packages, not a.no_compile, cache)
        a.output.write_text(json.dumps(sizes, indent=2, sort_keys=True) + "\n")
        print(f"wrote {a.output}", file=sys.stderr)
    elif a.cmd == "verify":
        raise SystemExit(verify(json.loads(a.committed.read_text()),
                                json.loads(a.measured.read_text()), a.workspace))
    elif a.cmd == "check":
        raise SystemExit(check(json.loads(a.sizes.read_text())))
    else:
        print(report(json.loads(a.base.read_text()),
                     json.loads(a.head.read_text()), a.base_ref))


if __name__ == "__main__":
    main()
