# Verifying a document proof

A proof is one Chonk proof of a *pipeline* folded by noir-zk's generic kernels. What a verifier checks is noir-zk's contract; what the identity layer adds is the meaning of the slots the DSC and document steps publish. This file is the identity layer's part; the pipeline's owner (the combining registry that declares it) documents the rest.

## What the verifier pins

- **The hiding kernel's key** (`noir_zk_backend::pipeline::hiding_vk()`, noir-zk's; the same for every pipeline of every registry at a noir-zk release).
- **A deployment root**: the root of the height-4 tree over the pipeline roots the combining registry declares (`DEPLOYMENT_ROOT` in its generated code). Adding a pipeline changes it; adding a circuit variant to a family changes that family's root and every pipeline root using it.

The proof's first public field is the deployment root, the second the pipeline root, the third the number of positions folded (so a pipeline root can't be used for a prefix of its pipeline), then 32 slots. `noir_zk_backend::pipeline::verify(proof, &PIPELINE, deployment_root, hiding_vk())` checks all of it and returns the fields; the combining registry's generated `<pipeline>::verify(&proof)` wraps it with the typed `Outputs`.

What the kernels have already enforced by then: every folded circuit's key is in its family's tree under the family's identity (library, version, layer, family), the family is at that position of the pipeline with that layout, the previous kernel is one of noir-zk's, the links chain (`c_A`, `c_B`, the payload commitment) and every binding and constant binding holds. The verifier never learns which variants were folded.

## The identity layer's slots

| slot | published by | the verifier checks |
|---|---|---|
| `registry_root` | `eid/dsc` | a published csca-registry root it still accepts (a ring of recent roots) |
| `date` | `eid/document` | the current date (unix seconds), within its tolerance; the document had not expired at it |
| `scope` | `eid/document` | its own nullifier scope, or 0 when it runs no Sybil check |
| `nullifier` | `eid/document` | not recorded in that scope before (then recorded); 0 when `scope` is 0 |

What the identity layer proves for those values is the statement in [ARCHITECTURE.md](ARCHITECTURE.md): a document issued under a CSCA registered under `registry_root`, valid at `date`, whose DG1 is committed in the payload commitment the document step leaves as its link. That commitment is private; the envelope app that continues it (in the reference pipeline zk-encryption's, sealing DG1 to the receiver on a post-quantum channel) publishes the ciphertext, and the pipeline binds it to the transfer it travels with. Those slots, the ciphertexts and the channel's values are the combining registry's to specify.

## Receiver

What a receiver opens, and how, is the envelope app's: in the reference pipeline the receiver rebuilds the channel's `Envelope` event from the session's and the envelopes' slots and opens DG1 with its chain key (zk-encryption's `Receiver::scan`). The identity layer only guarantees the plaintext behind the commitment is the DG1 whose hash the SOD lists: `[dg1_len, pack_be(DG1) × 4, 0]`, 95 bytes zero-padded.

## Toolchain

A proof verifies only with the bb version that produced it (7.0.0-nightly.20260927) and the kernels of the noir-zk release the registry was frozen with. Every bb bump is a new release of the circuits' keys and family roots; the verifier pins the new deployment root and hiding key in step.
