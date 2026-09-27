#!/usr/bin/env python3
"""Executes every end-to-end chain in noir/circuits/chains.json (the three
step circuits of one synthetic document, with the inputs eid-prover built in
their Chain.toml) and checks the steps' commitments link:

  DSC step [c_A, hash_id]  ->  SOD step [c_A, c_B, hash_id]  ->  envelope step sod_commitment = c_B

Only `nargo execute`; nothing is proven.

  check_chains.py [--nargo PATH]
"""

import argparse
import json
import re
import subprocess
import sys


def outputs(nargo: str, package: str) -> list[str]:
    r = subprocess.run([nargo, "execute", "--package", package, "--prover-name", "Chain"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout[-2000:], r.stderr[-2000:], file=sys.stderr)
        raise SystemExit(f"{package}: execution failed")
    line = next((l for l in r.stdout.splitlines() if "Circuit output:" in l), "")
    return re.findall(r"0x[0-9a-f]+", line)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--nargo", default="nargo")
    a = ap.parse_args()
    chains = json.load(open("noir/circuits/chains.json"))["chains"]
    bad = 0
    for c in chains:
        dsc, sod, env = (outputs(a.nargo, c[k]) for k in ("dsc", "sod", "envelope"))
        # Outputs { sod_commitment, econtent_hash_id, dg_hash_id, envelope }: sod_commitment first.
        links = {"DSC -> SOD (c_A)": dsc[0] == sod[0], "SOD -> envelope (c_B)": sod[1] == env[0]}
        for name, ok in links.items():
            if not ok:
                print(f"::error::{c['name']}: {name} does not link")
                bad += 1
        print(f"{c['name']}: {c['dsc']} -> {c['sod']} -> {c['envelope']}: "
              f"{'linked' if all(links.values()) else 'BROKEN'}", file=sys.stderr)
    raise SystemExit(1 if bad else 0)


if __name__ == "__main__":
    main()
