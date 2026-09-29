# Folding

The three steps are proven as one proof with Chonk, barretenberg's client-side IVC (the prover Aztec uses on phones). Every document keeps its exact, smallest step circuits: the DSC, SOD and document variants its signatures and sizes need. Yet every proof is verified under one key, noir-zk's hiding kernel's, so the verifier learns nothing about the variants and so nothing about the issuing country beyond what the public outputs say.

Since v0.8.0 the kernels are not this repository's. eid-circuits is an *identity layer*: three families of circuits with their record shapes, links and public slots, frozen as a [noir-zk](https://github.com/zk-experiments/noir-zk) layered registry. noir-zk's generic kernels (`kernel_init`, `kernel_step`, `kernel_tail`, `kernel_hiding`, crate `noir-zk-kernels`) fold any *pipeline* over any registries' families; a combining registry declares the pipelines (which envelope app opens the document's payload, what else is folded with it) and their deployment root. The reference pipeline is [postquantum-zk-encryption-experiment](https://github.com/zk-experiments/postquantum-zk-encryption-experiment): `[dsc, sod, document, session, envelope, transfer, note_envelope]`, with the channel layer from [zk-encryption](https://github.com/zk-experiments/zk-encryption).

## The families

| family | circuits | record (databus `return_data`) | link in | link out | public slots |
|---|---|---|---|---|---|
| `eid/dsc` | 124 DSC steps, `noir/circuits/dsc` | `[registry_root, c_A]` | none | `c_A` (`CA`) | `registry_root` |
| `eid/sod` | 124 SOD steps, `noir/circuits/sod` | `[c_A, c_B]` | `c_A` (`CA`) | `c_B` (`CB`) | none |
| `eid/document` | 48 document steps, `noir/circuits/document` | `[c_B, payload_commitment, date, scope, nullifier]` | `c_B` (`CB`) | `payload_commitment` (`PayloadCommitment`) | `date`, `scope`, `nullifier` |

They are declared in `rust/eid-circuits/circuits/manifest.toml` (`[[family]]`: members, links, `public_from`, slots) and generated into `eid_circuits::circuits::FAMILIES` with one marker type each (`KernelStepDsc`, `KernelStepSod`, `KernelStepDocument`), whose `select(label, toml)` accepts exactly the family's members.

- **Links.** A family continues the link the previous position left and leaves one of its own. The kernel asserts `record[link_in] == state.link` and sets `state.link = record[link_out]`, so `c_A` must reappear in the SOD step and `c_B` in the document step. The link types are checked at compile time by noir-zk's `PipelineFold` (`KernelStepSod` right after a position that left nothing doesn't compile) and at run time by the kernel (a wrong value makes the witness unsatisfiable: no proof exists). `PayloadCommitment` is noir-zk's shared link vocabulary (`noir_zk_core::pipeline::links`), so an envelope app of another library can continue it: `H("pq-channel/payload/v1/6", dg1_salt, [dg1_len, pack_be(DG1) × 4, 0])`, zk-encryption's `channel::payload::commit`.
- **Public slots.** The kernel appends `record[public_from .. public_from + n_pub]` to the pipeline's state; the hiding kernel publishes them all. The DSC step publishes the registry root, the document step the date, the scope and the nullifier; `c_A`, `c_B` and the payload commitment stay private.
- **Bindings.** These families bind nothing to earlier slots. A pipeline's envelope app is bound to the slots its session app published (ctx, C_t) by the same mechanism.

## Roots

A family's root is `H("noir-zk/family/v1", H(library, version, layer, family), tree)` with `tree` of height 8 over the sorted Poseidon2 hashes of its members' Chonk verification keys (`vk_hash` in the manifest, the 151 key fields hashed). The library identity is `eid-circuits@<version>` (`[library]` in the manifest, the release's version), so the same circuits in another release have other roots. A pipeline's tree (height 4) has one leaf per position, `H("noir-zk/position/v1", position, family_root, H(layout))`, with the kernels' family at the last leaf; a deployment tree (height 4) is over the pipeline roots a combining registry declares. The kernel checks every step's key in two steps (`pipeline_kernel::check_vk`): the key's hash in its family tree gives the family root, then `(position, family_root, layout hash)` under the pipeline root the state carries; the previous kernel is checked the same way under the kernels' family, and the hiding kernel proves the pipeline root under the deployment root.

This release's family roots are listed in [README.md](../README.md) and in every release's `catalog.json`.

## Public outputs

The hiding kernel publishes `[deployment_root, pipeline_root, length, slot × 32]` (35 fields, the proof's first 1,120 bytes): the slots in the order the pipeline's positions publish them. For the test-only pipeline `[dsc, sod, document]` of `rust/eid-circuits/tests/fold.rs` that is `[registry_root, date, scope, nullifier]`; a combining pipeline reads them through its generated `Outputs` struct. See [VERIFY.md](VERIFY.md).

## Toolchain notes

- **Versions.** Noir 1.0.0-rc.3 with bb 7.0.0-nightly.20260927, the nightly built on exactly rc.3's commit (pinned in `mise.toml`, installed per version under `~/.toolchains`), and noir-zk at the version `rust/Cargo.toml` pins (`=0.3.0`). Keys depend on the circuits and the bb version, so every family root changes with either.
- **No compatibility across bb versions.** A proof verifies only with the bb version that produced it. Every bb bump is a new release of the circuits' keys and family roots, and noir-zk's kernels move with it; the verifier must switch in step.
- **The SRS.** noir-zk derives keys and proves against a pinned SRS (2^20+1 BN254 points, 2^15 Grumpkin points in `~/.bb-crs`) and never downloads it: `mise run srs` provisions it (BN254 from Aztec's CRS host, Grumpkin from `resources/srs`).
- **No Solidity verifier.** bb has none for Chonk. Verification is native (`noir_zk_backend::pipeline::verify`, 20–30 ms), meant for a chain precompile.

## Running it

`mise run test:fold` folds, proves and verifies every chain of `noir/circuits/chains.json` (synthetic documents whose step inputs `eid-prover` built, `Chain.toml` in each selected package) in-process through noir-zk's `PipelineFold`, from the compiled samples in `target/`; CI does the same after executing the samples. `mise run fold:record` measures the same folds at 4 and all threads into `docs/data/fold-times.json` (never in CI).
