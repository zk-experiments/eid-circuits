# eid-circuits

Noir circuits that prove, for an encrypted identity document (passport, ID card, residence permit), that it was issued under a registered country signing CA (CSCA) and was valid on a given date. The document data (DG1, the MRZ) is encrypted to a set of viewer keys, and the encryption is proven correct. The CSCA registry, its Poseidon2 commitment and the Noir library that checks it come from [zk-experiments/csca-registry](https://github.com/zk-experiments/csca-registry).

All circuit code here is written for this repository and grouped by signature type. Every circuit and library has a specification README written for review; start with [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/FOLDING.md](docs/FOLDING.md), [docs/VERIFY.md](docs/VERIFY.md) and [docs/AUDIT.md](docs/AUDIT.md).

## Layout

| path | contents | status |
|---|---|---|
| `noir/lib/hash` | SHA-1/224/256/384/512 over variable-length input, `Digest` trait | done |
| `noir/lib/rsa` | RSASSA-PKCS1-v1_5 and RSASSA-PSS over noir-bignum | done |
| `noir/lib/ecdsa` | ECDSA on P-256/384/521, brainpoolP256/384/512r1 | done |
| `noir/lib/envelope` | Grumpkin ECDH per viewer, key wrap, Poseidon2 duplex encryption | done |
| `noir/lib/der` | constrained DER reading: `TBSCertificate`s, public keys, CMS signed attributes, LDS security objects | done |
| `noir/lib/steps` | shared step checks (DSC, SOD, envelope) and the commitments linking them | done |
| `noir/lib/kernel`, `noir/kernels/…` | Chonk folding: kernels checking the key tree and step links; the hiding kernel's public outputs | done |
| `noir/circuits/dsc/…` | DSC step: 124 circuits (31 CSCA signing configurations × 4 size buckets) | done |
| `noir/circuits/sod/…` | SOD step: 124 circuits (31 DSC signing configurations × 4 size buckets) | done |
| `noir/circuits/envelope/…` | envelope step: 48 circuits (16 hash pairs × 3 eContent buckets) | done |
| `noir/bench` | one benchmark circuit per signature group and hash; gates and opcodes in CI | done |
| `noir/vendor/sha512` | `noir-lang/sha512` at a pinned commit | vendored |
| `noir/vendor/noir_bigcurve` | `noir-lang/noir_bigcurve` v0.14.0 plus generated curves | vendored |
| `rust/eid-vectors` | test-vector generator (real certificates from master lists, synthetic documents) | done |
| `rust/eid-envelope` | envelope encryption for provers (`seal`) and viewers (`open`) | done |
| `rust/eid-prover` | from the NFC read (EF.SOD, DG1): circuit selection, native pre-checks, and the inputs of all three steps | done |
| `rust/eid-circuits` | the frozen circuits as typed bindings for [noir-zk](https://github.com/zk-experiments/noir-zk)'s backend (generated `Inputs` / `Outputs`, `App` / `Kernel`, static label dispatch) | done |

## Build and test

```sh
mise run install:zk-toolchain  # nargo and bb at the pinned versions, into ~/.toolchains/<tool>-<version> (not ~/.nargo, ~/.bb)
"$NARGO" test                  # every Noir package in the workspace (nargo from mise.toml; `mise env` sets NARGO and BB)
cd rust && cargo test          # Rust tools, incl. the check that generated files are current
mise run circuit-sizes         # refresh docs/data/circuit-sizes.json (CI checks it for the samples)
mise run vk-tree               # refresh the verification key tree the kernels check (noir/circuits/vk-tree.json)
scripts/fold.py                # execute the synthetic documents through the folding kernels (CI does this)
scripts/fold.py --prove --threads 4,18 --record docs/data/fold-times.json --machine "<machine>"   # Chonk proofs, timed
```

## Proving from Rust

`rust/eid-circuits` holds the frozen circuits as bindings for noir-zk's backend (ACVM witness solving and Chonk folding over the bb FFI, no `nargo` or `bb` binaries). Its circuits are frozen with the noir-zk CLI. Keys, ABIs and the key tree are committed under `rust/eid-circuits`. The bytecode (about 730 MB) goes to the `circuits` release as `<label>@<version>.b64`, and every asset is checked against its pinned SHA-256 before use.

```sh
mise run freeze                 # after vk-tree: mint versions for changed circuits (-- --abi-change for ABI changes)
mise run freeze -- --check      # fail if rust/eid-circuits is behind target/
mise run assets:publish         # upload new bytecode assets
mise run test:prove             # prove and verify every chain with the frozen registry
```

```rust
use eid_circuits::circuits::{kernel_dsc::KernelDsc, kernel_envelope::KernelEnvelope, kernel_hiding::KernelHiding, kernel_sod::KernelSod, kernel_tail::KernelTail, Registry};
use noir_zk_backend::fold::{verify, Folding};

let w = eid_prover::witnesses(&registry, ef_sod, dg1, &params)?;   // selection + Prover.toml per step
let (proof, public) = Folding::new(&eid_circuits::artifacts(DirStore(assets))?)
    .app_by_label::<Registry, _>(&w.selection.dsc, &w.dsc)?
    .kernel::<KernelDsc>()?
    .app_by_label::<Registry, _>(&w.selection.sod, &w.sod)?
    .kernel::<KernelSod>()?
    .app_by_label::<Registry, _>(&w.selection.envelope, &w.envelope)?
    .kernel::<KernelEnvelope>()?
    .kernel::<KernelTail>()?
    .hiding::<KernelHiding>()?;
let public = verify::<KernelHiding>(&proof, eid_circuits::vk_tree_root())?;   // KernelHiding::Outputs
```

The chain is typed: each kernel only compiles after the kernel and app whose outputs it takes. The step circuits are chosen at runtime, and `Registry` dispatches each label to its generated type statically.

noir-zk is a private git dependency: locally, git needs credentials for https://github.com/zk-experiments/noir-zk. CI reads it with the `NOIR_ZK_TOKEN` secret. On Linux, bb's static library needs libc++ (`libc++-dev libc++abi-dev`).

Generated files (Noir vectors, curves, circuits, root `Nargo.toml`, `docs/COSTS.md`) come from `rust/eid-vectors`; see its `--help`. Per-country proving cost estimates for mobile are in [docs/COSTS.md](docs/COSTS.md).
