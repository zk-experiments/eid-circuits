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

## Getting started

All tooling is pinned and installed by [mise](https://mise.jdx.dev), so start there:

1. Install mise: `curl https://mise.run | sh` (or `brew install mise`), then activate it in your shell (`mise activate`, see its docs).
2. In this repository, trust its config and install the tools: `mise trust && mise install` (Node and wrangler, for R2 uploads).
3. Install the zero-knowledge toolchain: `mise run install:zk-toolchain install:noir-zk`. This installs nargo and bb at the pinned versions into `~/.toolchains/<tool>-<version>`, not `~/.nargo` or `~/.bb`, and the noir-zk CLI at the version `rust/Cargo.toml` pins.

`mise env` sets `NARGO` and `BB` to the pinned binaries. Every task below documents its raw command in `mise.toml`.

## Build and test

```sh
"$NARGO" test                  # every Noir package in the workspace (nargo from mise.toml; `mise env` sets NARGO and BB)
cd rust && cargo test          # Rust tools, incl. the check that generated files are current
mise run circuit-sizes         # refresh docs/data/circuit-sizes.json (CI checks it for the samples)
mise run vk-tree               # refresh the verification key tree the kernels check (noir/circuits/vk-tree.json)
scripts/fold.py                # execute the synthetic documents through the folding kernels (CI does this)
scripts/fold.py --prove --threads 4,18 --record docs/data/fold-times.json --machine "<machine>"   # Chonk proofs, timed
```

## Proving from Rust

`rust/eid-circuits` holds the frozen circuits as bindings for noir-zk's backend (ACVM witness solving and Chonk folding over the bb FFI, no `nargo` or `bb` binaries). Its circuits are frozen with the noir-zk CLI. Keys, ABIs and the key tree are committed under `rust/eid-circuits`. The bytecode (about 570 MB) is not: it's published as circuit packs, and every asset is checked against its pinned SHA-256 before use.

```sh
mise run freeze                 # after vk-tree: mint versions for changed circuits (-- --abi-change for ABI changes)
mise run freeze -- --check      # fail if rust/eid-circuits is behind target/
mise run test:prove             # prove and verify every chain with the frozen registry
```

### Circuit packs

A prover fetches packs, not single circuits: fetching exactly its document's circuits would tell the download host the document's configuration, while a pack tells it only a key family that many countries share. `rust/eid-circuits/circuits/packs.toml` (generated by `eid-vectors packs`) defines them:

- `common`: every envelope circuit and the kernels (69 MB);
- one pack per key family (`rsa2048` … `rsa6144`, `p256`, `p384`, `p521`, `bp256`, `bp384`, `bp512`; 7–137 MB): the DSC and SOD circuits of every configuration with that key;
- `[countries]`: each country's CSCA key families.

A document needs `common`, its CSCA key's family and its DSC key's; `eid_prover::select` returns them as `Selection::packs`. Each pack is a self-contained `<pack>@<version>.tar.gz`: per circuit its bytecode, verification key and ABI, plus the key tree and the manifest entries with their pinned hashes. The client unpacks it with `noir_zk_backend::pack::unpack` and reads it with `DirStore`.

Every release publishes them, from CI: it compiles every circuit from the tagged source, fails unless each matches its pin, builds the packs and uploads them to the GitHub release and to `https://circuits.zk-eid.dev` (`eid_circuits::PACKS_URL`):

- `catalog.json`: the latest release's catalog (cached for 5 minutes), the index a client reads first: each pack's file, SHA-256, size and circuits, the country map, the toolchain and the key tree root;
- `catalog@<version>.json`, `<pack>@<version>.tar.gz`, `vk-tree@<version>.json`: immutable.

A client reads `catalog.json`, downloads the packs `Selection::packs` names, checks each archive's SHA-256 against the catalog, and unpacks it. By hand, on a release tag:

```sh
mise run compile && mise run freeze -- --check && mise run freeze   # bytecode from source, checked against the pins
mise run packs                  # target/packs: every pack, the catalog and vk-tree@<version>.json
mise run packs:publish          # upload them to the GitHub release v<version>
mise run packs:publish-r2       # and to the circuits R2 bucket (R2_CIRCUITS_BUCKET, R2_CIRCUITS_TOKEN, R2_ACCOUNT_ID)
```

```rust
use eid_circuits::circuits::{kernel_dsc::KernelDsc, kernel_envelope::KernelEnvelope, kernel_hiding::KernelHiding, kernel_sod::KernelSod, kernel_tail::KernelTail};
use noir_zk_backend::fold::{verify, Folding};

let w = eid_prover::witnesses(&registry, ef_sod, dg1, &params)?;   // selected labels + Prover.toml per step
let (proof, public) = Folding::new(&eid_circuits::artifacts(DirStore(assets))?)
    .app(KernelDsc::select(&w.selection.dsc, &w.dsc)?)?
    .app(KernelSod::select(&w.selection.sod, &w.sod)?)?
    .app(KernelEnvelope::select(&w.selection.envelope, &w.envelope)?)?
    .kernel::<KernelTail>()?
    .hiding::<KernelHiding>()?;
let public = verify::<KernelHiding>(&proof, eid_circuits::vk_tree_root())?;   // kernel_hiding::Outputs
```

Each step is wrapped with the kernel that folds it, and the chain is checked at compile time. `KernelDsc::select` dispatches the runtime-selected label statically to its generated circuit type and rejects labels that aren't DSC apps. `KernelDsc::wrap::<C>(&inputs)` does the same for a circuit known at compile time.

On Linux, bb's static library needs libc++ (`libc++-dev libc++abi-dev`).

Generated files (Noir vectors, curves, circuits, root `Nargo.toml`, `docs/COSTS.md`) come from `rust/eid-vectors`; see its `--help`. Per-country proving cost estimates for mobile are in [docs/COSTS.md](docs/COSTS.md).
