# eid-circuits

Noir circuits that prove, for an electronic identity document (passport, ID card, residence permit), that it was issued under a registered country signing CA (CSCA) and was valid on a given date, and that commit to the document data (DG1, the MRZ) for an encryption step to seal. The CSCA registry, its Poseidon2 commitment and the Noir library that checks it come from [zk-experiments/csca-registry](https://github.com/zk-experiments/csca-registry).

Since v0.8.0 this is an *identity layer*: three families of circuits (`eid/dsc`, `eid/sod`, `eid/document`) frozen as a [noir-zk](https://github.com/zk-experiments/noir-zk) layered registry, folded by noir-zk's generic kernels as positions of a pipeline a combining registry declares. Encryption is another layer, [zk-encryption](https://github.com/zk-experiments/zk-encryption) (a post-quantum channel and the envelope app that opens this layer's DG1 commitment); the reference pipeline that folds both with a private transfer is [postquantum-zk-encryption-experiment](https://github.com/zk-experiments/postquantum-zk-encryption-experiment).

All circuit code here is written for this repository and grouped by signature type. Every circuit and library has a specification README written for review; start with [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/FOLDING.md](docs/FOLDING.md), [docs/VERIFY.md](docs/VERIFY.md) and [docs/AUDIT.md](docs/AUDIT.md).

## Layout

| path | contents | status |
|---|---|---|
| `noir/lib/hash` | SHA-1/224/256/384/512 over variable-length input, `Digest` trait | done |
| `noir/lib/rsa` | RSASSA-PKCS1-v1_5 and RSASSA-PSS over noir-bignum | done |
| `noir/lib/ecdsa` | ECDSA on P-256/384/521, brainpoolP256/384/512r1 | done |
| `noir/lib/der` | constrained DER reading: `TBSCertificate`s, public keys, CMS signed attributes, LDS security objects | done |
| `noir/lib/steps` | shared step checks (DSC, SOD, document) and the commitments linking them; the document step's payload commitment uses zk-encryption's `channel` library | done |
| `noir/circuits/dsc/…` | DSC step: 124 circuits (31 CSCA signing configurations × 4 size buckets) | done |
| `noir/circuits/sod/…` | SOD step: 124 circuits (31 DSC signing configurations × 4 size buckets) | done |
| `noir/circuits/document/…` | document step: 48 circuits (16 hash pairs × 3 eContent buckets) | done |
| `noir/bench` | one benchmark circuit per signature group and hash; gates and opcodes in CI | done |
| `noir/vendor/sha512` | `noir-lang/sha512` at a pinned commit | vendored |
| `noir/vendor/noir_bigcurve` | `noir-lang/noir_bigcurve` v0.14.0 plus generated curves | vendored |
| `rust/eid-vectors` | test-vector generator (real certificates from master lists, synthetic documents) | done |
| `rust/eid-prover` | from the NFC read (EF.SOD, DG1): circuit selection, native pre-checks, and the inputs of all three steps | done |
| `rust/eid-circuits` | the identity layer: the frozen circuits as a noir-zk layered registry (families with their roots, `KernelStepDsc/Sod/Document` with static label dispatch, typed `Inputs` / `Outputs`), and the fold test over the test-only pipeline `[dsc, sod, document]` | done |
| `resources/srs` | the 2^15-point Grumpkin CRS prefix noir-zk pins (`mise run srs`) | done |

## Getting started

All tooling is pinned and installed by [mise](https://mise.jdx.dev), so start there:

1. Install mise: `curl https://mise.run | sh` (or `brew install mise`), then activate it in your shell (`mise activate`, see its docs).
2. In this repository, trust its config and install the tools: `mise trust && mise install` (aws-cli, for R2 uploads).
3. Install the zero-knowledge toolchain: `mise run install:zk-toolchain install:noir-zk`. This installs nargo and bb at the pinned versions into `~/.toolchains/<tool>-<version>`, not `~/.nargo` or `~/.bb`, and the noir-zk CLI from crates.io at the version `rust/Cargo.toml` pins (`=0.3.0`).

`mise env` sets `NARGO` and `BB` to the pinned binaries. Every task below documents its raw command in `mise.toml`.

## Build and test

```sh
"$NARGO" test                  # every Noir package in the workspace (nargo from mise.toml; `mise env` sets NARGO and BB)
cd rust && cargo test          # Rust tools, incl. the check that generated files are current
mise run circuit-sizes         # refresh docs/data/circuit-sizes.json (CI checks it for the samples)
mise run srs                   # the SRS noir-zk pins, into ~/.bb-crs (once)
mise run test:fold             # fold, prove and verify the synthetic documents through noir-zk's kernels (CI does this)
mise run fold:record           # the same, timed at 4 and all threads, into docs/data/fold-times.json (never in CI)
```

## The layer, from Rust

`rust/eid-circuits` is the identity layer as a noir-zk layered registry: `circuits/manifest.toml` (written by `noir-zk freeze`, with the three `[[family]]` tables hand-written and kept) and `resources/` (ABIs and Chonk verification keys) are committed; `build.rs` generates `eid_circuits::circuits::{REGISTRY, FAMILIES, LIBRARY}`, one marker type per family (`families::{KernelStepDsc, KernelStepSod, KernelStepDocument}`, each a `StepFamily` whose `select(label, toml)` accepts exactly its members) and the typed `Inputs` / `Outputs` per circuit. There are no kernels and no pipelines here: noir-zk's kernels (`noir_zk_backend::kernels`, bundled in its crate) fold any pipeline over these families, and a combining registry declares the pipelines, wrapping this registry with `noir_zk_codegen::wrapped(LIBRARY, REGISTRY, FAMILIES)`. The bytecode (about 760 MB of base64 release assets, 535 MB as gzipped packs) is not committed: it's published as circuit packs, and every asset is checked against its pinned SHA-256 before use.

```sh
mise run freeze                 # mint versions for changed circuits as eid-circuits@<version> (-- --abi-change for ABI changes)
mise run freeze -- --check      # fail if rust/eid-circuits is behind target/
mise run test:fold              # fold, prove and verify every chain from target/ (mise run test:prove: from target/release-assets, pins checked)
```

| family | members | record | link in → out | public slots | root (eid-circuits@0.8.0) |
|---|---:|---|---|---|---|
| `eid/dsc` | 124 | `[registry_root, c_A]` | — → `CA` | `registry_root` | `0x12ae4ab07a194116691e3c934436e624bb260136294e9613faf6dbcba450b651` |
| `eid/sod` | 124 | `[c_A, c_B]` | `CA` → `CB` | — | `0x151589d2dea975e5903a6db549fcd986aedf91a40581db09b5917a08bd6364d7` |
| `eid/document` | 48 | `[c_B, payload_commitment, date, scope, nullifier]` | `CB` → `PayloadCommitment` | `date`, `scope`, `nullifier` | `0x293782c28e7c6816534cae20c49658157ba286c7d58bf7c9bcbfc63b68b928e1` |

A family's root is `H("noir-zk/family/v1", H("eid-circuits", "0.8.0", layer, family), tree)` over the sorted key hashes of its members ([docs/FOLDING.md](docs/FOLDING.md)); every release's `catalog.json` lists them. In a combining registry:

```toml
[[family]]                 # the wrapped families come with their definitions
layer = "eid"
name = "document"
source = "eid-circuits"

[[pipeline]]
name = "identity_envelope"
positions = ["eid-circuits/eid/dsc", "eid-circuits/eid/sod", "eid-circuits/eid/document", "zk-encryption/channel/session", "zk-encryption/channel/envelope"]
```

```rust
use eid_circuits::circuits::families::{KernelStepDocument, KernelStepDsc, KernelStepSod};
use noir_zk_core::StepFamily;

let w = eid_prover::witnesses(&registry, ef_sod, dg1, &params)?;   // selected labels + Prover.toml per step
let pool = noir_zk_core::Merged::new(&[&eid_circuits::artifacts(DirStore(assets)), &channel, &noir_zk_backend::kernels::Kernels]);
let (proof, _) = identity_envelope::fold(&pool)?                    // the combining registry's generated pipeline
    .app(KernelStepDsc::select(&w.selection.dsc, w.dsc)?)?
    .app(KernelStepSod::select(&w.selection.sod, w.sod)?)?
    .app(KernelStepDocument::select(&w.selection.document, w.document)?)?
    .app(/* the channel layer's session and envelope apps */)?
    .hiding(&DEPLOYMENT)?;
let out = identity_envelope::verify(&proof)?;                       // hiding key, deployment root, pipeline root, length; then out.registry_root, out.date, out.scope, out.nullifier, ...
```

The chain is checked at compile time (`KernelStepSod` right after `fold()` doesn't compile: its link in is `CA`) and by the kernels at run time (a label outside the family, a wrong link value or a broken binding leaves no proof). `rust/eid-circuits/tests/fold.rs` builds the test-only pipeline `[dsc, sod, document]` at run time and folds every synthetic chain through it.

On Linux, bb's static library needs libc++ (`libc++-dev libc++abi-dev`).

### Circuit packs

A prover fetches packs, not single circuits: fetching exactly its document's circuits would tell the download host the document's configuration, while a pack tells it only a key family that many countries share. `rust/eid-circuits/circuits/packs.toml` (generated by `eid-vectors packs`) defines them:

- `common`: every document step circuit (the kernels are noir-zk's, bundled in its crate);
- one pack per key family (`rsa2048` … `rsa6144`, `p256`, `p384`, `p521`, `bp256`, `bp384`, `bp512`; 7–137 MB): the DSC and SOD circuits of every configuration with that key;
- `[countries]`: each country's CSCA key families.

A document needs `common`, its CSCA key's family and its DSC key's; `eid_prover::select` returns them as `Selection::packs`. Each pack is a self-contained `<pack>@<version>.tar.gz`: per circuit its bytecode, verification key and ABI, plus the manifest entries with their pinned hashes. The client unpacks it with `noir_zk_backend::pack::unpack` and reads it with `DirStore`.

Instead of downloading packs, a build can compile circuits into the binary. With the `eid-circuits` feature `bundled`, `build.rs` compiles the chosen packs from the Noir source shipped with the crate, fails unless every result hashes to its pin, and embeds them (`eid_circuits::bundled::BundledStore`). It needs the pinned nargo (step 3 of getting started; `mise exec --` or an activated mise sets `$NARGO`) and network access for the Noir libraries' git dependencies. `EID_CIRCUITS_BUNDLE` picks the packs (`common,rsa4096`; unset: all, which takes over an hour; `none`: nothing):

```sh
EID_CIRCUITS_BUNDLE=common,rsa4096 mise exec -- cargo build --release -p eid-circuits --features bundled
```

Every release publishes them, from CI: it compiles every circuit from the tagged source, fails unless each matches its pin, builds the packs and uploads them to the GitHub release and to `https://circuits.zk-eid.dev` (`eid_circuits::PACKS_URL`):

- `catalog.json`: the latest release's catalog (cached for 5 minutes), the index a client reads first: each pack's file, SHA-256, size and circuits, the country map and the toolchain;
- `catalog@<version>.json`, `<pack>@<version>.tar.gz`: immutable.

A client reads `catalog.json`, downloads the packs `Selection::packs` names, checks each archive's SHA-256 against the catalog, unpacks it, and checks the files against the pins compiled into this crate: `noir_zk_backend::frozen::verify_dir(eid_circuits::circuits::REGISTRY, dir)` (every circuit's `BYTECODE_SHA256` and `VK_SHA256`, also listed per version in `circuits/manifest.toml`). The catalog and the hosts are only for finding files; the crate is what a client trusts. Each release's notes list its packs with their links and SHA-256. By hand, on a release tag:

```sh
mise run compile && mise run srs    # bytecode from source; the SRS noir-zk pins, in ~/.bb-crs
mise run freeze -- --check && mise run freeze   # checked against the pins
mise run packs                  # target/packs: every pack and the catalog
mise run packs:publish          # upload them to the GitHub release v<version>
mise run packs:publish-r2       # and to the circuits R2 bucket (R2_CIRCUITS_BUCKET, R2_CIRCUITS_TOKEN, R2_ACCOUNT_ID)
```

Generated files (Noir vectors, curves, circuits, root `Nargo.toml`, `docs/COSTS.md`) come from `rust/eid-vectors`; see its `--help`. Per-country proving cost estimates for mobile are in [docs/COSTS.md](docs/COSTS.md).

## Release blockers (v0.8.0)

- **zk-encryption's channel library.** `noir/lib/steps` takes `channel` from zk-encryption at `tag = "v0.1.0"` (the payload commitment's domain and layout); a new tag there is a refreeze here.
