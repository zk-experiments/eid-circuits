#!/usr/bin/env python3
"""Runs the end-to-end chains of noir/circuits/chains.json through the kernels
that fold them with Chonk (docs/FOLDING.md):

  DSC step -> kernel_dsc -> SOD step -> kernel_sod -> envelope step
           -> kernel_envelope -> kernel_tail -> kernel_hiding

Each step executes with the prover's inputs in its Chain.toml; each kernel's
inputs (the previous databus outputs, verification keys and their key tree
paths from noir/circuits/vk-tree.json) are written to Fold.toml in the
kernel's package and executed, so the kernels' checks (key tree membership,
step links) run for real. With --prove, the eight circuits are packed into
bb's IVC input stack and proven and verified with Chonk.

  scripts/fold.py [--chain NAME] [--prove [--threads 4,18] [--record FILE --machine TEXT]]
                  [--nargo PATH] [--bb PATH]

--record writes the measured runs (time, peak memory, total and largest
circuit gates) for docs/data/fold-times.json, which `eid-vectors costs` reads.

CI runs it without --prove: nothing is proven there.
"""

import argparse
import base64
import json
import os
import re
import subprocess
import sys
import tempfile
import time

KERNELS = ["kernel_dsc", "kernel_sod", "kernel_envelope", "kernel_tail", "kernel_hiding"]


def run(cmd, env=None):
    r = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if r.returncode != 0:
        sys.exit(f"$ {' '.join(cmd)}\n{r.stdout[-3000:]}\n{r.stderr[-3000:]}")
    return r.stdout + r.stderr


class Folder:
    def __init__(self, nargo, bb, work):
        self.nargo, self.bb, self.work = nargo, bb, work
        self.tree = json.load(open("noir/circuits/vk-tree.json"))
        self.leaves = {l["package"]: l for l in self.tree["leaves"]}

    def execute(self, package, prover):
        out = run([self.nargo, "execute", "--package", package, "--prover-name", prover])
        line = next((l for l in out.splitlines() if "Circuit output:" in l), "")
        return re.findall(r"0x[0-9a-f]+", line)

    def vk(self, package, zk=False):
        """Chonk verification key: (field strings, binary key path)."""
        d = os.path.join(self.work, package)
        flags = ["--use_zk_flavor"] if zk else []
        art = f"target/{package}.json"
        run([self.bb, "write_vk", "--scheme", "chonk", *flags, "-b", art, "-o", d, "--output_format", "json"])
        run([self.bb, "write_vk", "--scheme", "chonk", *flags, "-b", art, "-o", d])
        return json.load(open(os.path.join(d, "vk.json")))["vk"], os.path.join(d, "vk")

    def vk_table(self, package, fields):
        leaf = self.leaves.get(package)
        if leaf is None:
            sys.exit(f"{package} is not in noir/circuits/vk-tree.json; run `eid-vectors vk-tree`")
        return {"key": fields, "path": {"index": str(leaf["index"]), "siblings": leaf["siblings"]}}

    def kernel(self, name, inputs):
        """Writes Fold.toml for a kernel and executes it."""
        path = f"noir/kernels/{name.removeprefix('kernel_')}/Fold.toml"
        with open(path, "w") as f:
            f.write("# Written by scripts/fold.py; not committed.\n" + toml(inputs))
        return self.execute(name, "Fold")


def toml(inputs, prefix=""):
    """Minimal TOML for flat values, arrays and nested tables."""
    flat, tables = [], []
    for k, v in inputs.items():
        if isinstance(v, dict):
            tables.append((k, v))
        elif isinstance(v, list):
            flat.append(f"{k} = [{', '.join(json.dumps(str(x)) for x in v)}]")
        else:
            flat.append(f"{k} = {json.dumps(str(v))}")
    out = "\n".join(flat) + "\n"
    for k, v in tables:
        name = f"{prefix}{k}"
        out += f"\n[{name}]\n" + toml(v, name + ".")
    return out


def fold(f, chain, prove, threads, runs):
    name = chain["name"]
    steps = [chain["dsc"], chain["sod"], chain["envelope"]]
    outs = [f.execute(p, "Chain") for p in steps]
    vks = [f.vk(p) for p in steps]
    root = f.tree["root"]
    s = f.kernel("kernel_dsc", {"step": outs[0], "vk_tree_root": root,
                                "step_vk": f.vk_table(steps[0], vks[0][0])})
    kvk = f.vk("kernel_dsc")
    s = f.kernel("kernel_sod", {"prev": s, "step": outs[1],
                                "prev_vk": f.vk_table("kernel_dsc", kvk[0]),
                                "step_vk": f.vk_table(steps[1], vks[1][0])})
    kvk2 = f.vk("kernel_sod")
    s = f.kernel("kernel_envelope", {"prev": s, "step": outs[2],
                                     "prev_vk": f.vk_table("kernel_sod", kvk2[0]),
                                     "step_vk": f.vk_table(steps[2], vks[2][0])})
    kvk3 = f.vk("kernel_envelope")
    s = f.kernel("kernel_tail", {"prev": s, "prev_vk": f.vk_table("kernel_envelope", kvk3[0])})
    kvk4 = f.vk("kernel_tail")
    public = f.kernel("kernel_hiding", {"prev": s, "prev_vk": f.vk_table("kernel_tail", kvk4[0])})
    # PublicOutputs: registry root, key tree root, uses_sha1, date, context, ...
    expect = [outs[0][0], root]
    if [int(x, 16) for x in public[:2]] != [int(x, 16) for x in expect]:
        sys.exit(f"{name}: public outputs {public[:2]} don't match {expect}")
    print(f"{name}: folded through the kernels; public outputs {len(public)} fields", file=sys.stderr)
    if not prove:
        return
    import msgpack  # only needed for proving
    hvk = f.vk("kernel_hiding", zk=True)
    order = [(steps[0], vks[0][1], 0), ("kernel_dsc", kvk[1], 1), (steps[1], vks[1][1], 0),
             ("kernel_sod", kvk2[1], 1), (steps[2], vks[2][1], 0), ("kernel_envelope", kvk3[1], 1),
             ("kernel_tail", kvk4[1], 1), ("kernel_hiding", hvk[1], 2)]
    stack = [{"bytecode": base64.b64decode(json.load(open(f"target/{p}.json"))["bytecode"]),
              "witness": open(f"target/{p}.gz", "rb").read(),
              "vk": open(vk, "rb").read(), "functionName": p, "kind": kind}
             for p, vk, kind in order]
    ivc = os.path.join(f.work, f"{name}.msgpack")
    open(ivc, "wb").write(msgpack.packb(stack, use_bin_type=True))
    sizes = json.load(open("docs/data/circuit-sizes.json"))
    gates = [sizes[p]["gates"] for p, _, _ in order]
    for th in threads:
        out = os.path.join(f.work, f"{name}-proof-{th}")
        env = dict(os.environ, HARDWARE_CONCURRENCY=str(th))
        log = run(["/usr/bin/time", "-l" if sys.platform == "darwin" else "-v", f.bb, "prove",
                   "--scheme", "chonk", "--ivc_inputs_path", ivc, "-o", out, "--write_vk"], env)
        m = re.search(r"([\d.]+) real", log)
        if m:
            secs = float(m.group(1))
        else:
            h, mi, sec = ([0, 0] + re.search(r"Elapsed \(wall clock\) time.*: ([\d:.]+)", log).group(1).split(":"))[-3:]
            secs = int(h) * 3600 + int(mi) * 60 + float(sec)
        peak = re.search(r"(\d+)\s+peak memory footprint", log)
        peak = int(peak.group(1)) if peak else int(re.search(r"Maximum resident set size \(kbytes\): (\d+)", log).group(1)) * 1024
        verified = run([f.bb, "verify", "--scheme", "chonk", "-p", f"{out}/proof", "-k", f"{out}/vk", "-v"])
        if "verified: 1" not in verified:
            sys.exit(f"{name}: the Chonk proof does not verify")
        print(f"{name}: {th} threads: Chonk proof {os.path.getsize(f'{out}/proof')} bytes, "
              f"{secs:.2f} s, peak {peak / 2**20:.0f} MiB, verified", file=sys.stderr)
        runs.append({"chain": name, "threads": th, "seconds": secs, "peak_bytes": peak,
                     "total_gates": sum(gates), "max_gates": max(gates)})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chain")
    ap.add_argument("--prove", action="store_true")
    ap.add_argument("--nargo", default="nargo")
    ap.add_argument("--bb", default="bb")
    ap.add_argument("--threads", default="4", help="comma-separated thread counts to prove with")
    ap.add_argument("--record", help="write the measured runs to this JSON file")
    ap.add_argument("--machine", default="unknown machine")
    a = ap.parse_args()
    chains = json.load(open("noir/circuits/chains.json"))["chains"]
    if a.chain:
        chains = [c for c in chains if c["name"] == a.chain]
    threads = [int(t) for t in a.threads.split(",")]
    runs = []
    with tempfile.TemporaryDirectory() as work:
        f = Folder(a.nargo, a.bb, work)
        for c in chains:
            fold(f, c, a.prove, threads, runs)
    if a.record:
        bb = run([a.bb, "--version"]).strip()
        nargo = run([a.nargo, "--version"]).splitlines()[0].split()[-1]
        doc = {"machine": a.machine, "bb": bb, "nargo": nargo,
               "date": time.strftime("%Y-%m-%d", time.gmtime()), "runs": runs}
        open(a.record, "w").write(json.dumps(doc, indent=2) + "\n")
        print(f"wrote {a.record}", file=sys.stderr)


if __name__ == "__main__":
    main()
