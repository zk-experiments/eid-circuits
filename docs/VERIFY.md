# Verifying a document proof

A document proof is one Chonk proof: the three steps folded with the kernels described in [FOLDING.md](FOLDING.md). It is verified natively (`bb verify --scheme chonk`, 20–30 ms) against the hiding kernel's verification key. That's the same key for every document, whatever signature schemes and sizes it used. There is no Solidity verifier for Chonk; verification is meant for a chain precompile.

## Bundle

A transfer carrying a document submits the Chonk proof and its public outputs (`eid_kernel::PublicOutputs`):

| output | meaning |
|---|---|
| `registry_root` | csca-registry root the CSCA and revocation checks used |
| `vk_tree_root` | root of the key tree every step and kernel was checked against |
| `date`, `context` | proof date and the context the envelope is bound to |
| `viewer` | the Grumpkin key the envelope is sealed to: the receiver's, fresh per transfer |
| `ephemeral`, `wrapped`, `ciphertext` | the envelope: `E`, the wrapped data key, six ciphertext fields |
| `scope`, `nullifier` | the scope the proof was made for (0 for none), and the document's nullifier in it (0 for scope 0) |

## Parameters

bb 7.0.0-nightly.20260927 (Noir 1.0.0-rc.3), measured on the four synthetic documents:

| | size |
|---|---|
| proof | 39,616 bytes (1,238 field elements), the same for every document |
| public inputs | 17 field elements, the first 544 bytes of the proof (below) |
| hiding kernel verification key | 3,808 bytes, the same for every document |
| verification | 20–30 ms native (`bb verify --scheme chonk -p proof -k vk`) |

The public outputs are the proof's first 17 fields, 32 bytes each, big-endian, in this order:

| field | offset | content |
|---:|---:|---|
| 0 | 0 | `registry_root` |
| 1 | 32 | `vk_tree_root` |
| 2 | 64 | `date` (unix seconds) |
| 3 | 96 | `context` |
| 4–5 | 128 | `viewer`: (x, y), a Grumpkin point, never `(0, 0)` |
| 6–7 | 192 | envelope `E` = (x, y) |
| 8 | 256 | envelope `wrapped` |
| 9–14 | 288 | envelope `ciphertext` × 6 |
| 15 | 480 | `scope` (0 for none) |
| 16 | 512 | `nullifier` (0 when `scope` is 0) |

The envelope itself is fields 6–14, 288 bytes, fixed for every document; with the viewer key, 352 bytes. Changing any of these bytes makes the proof fail to verify.

A proof verifies only with the bb version that made it (bb 7 rejects bb 5 proofs and the reverse), so a verifier pins one bb version, and a bb upgrade switches the verifier at a cutover. A node replaying history needs the verifier of each past version.

## Checks

The verifier accepts the bundle only if all of these hold:

1. **The proof verifies** under the pinned hiding kernel key.
2. **`vk_tree_root` is the published key tree root** (`noir/circuits/vk-tree.json` for the release in use). The tree fixes which circuits may be used, so it must be pinned like the hiding kernel key.
3. **`registry_root` is a published registry root** the verifier still accepts: the current one, or one within a short window, so revocations take effect.
4. **`date` is now**, within the verifier's tolerance. The envelope step proves the document hasn't expired at `date`.
5. **`context` identifies this transfer.** It's chosen before proving (for example `H(chain id, contract, sender, nonce)` or the transfer's note commitment; it can't be the transaction hash, which depends on the proof). The envelope is encrypted under it, so a bundle copied to another transfer fails this check, and the receiver needs `context` to decrypt.
6. **Sybil check, if the verifier runs one.** `scope` must be the verifier's own (for example `H(chain id, contract, purpose)`), and `nullifier` must not be recorded in that scope yet; then the verifier records it. A verifier without a Sybil check requires `scope = 0` (so `nullifier = 0`, and proofs stay unlinkable). The nullifier is per document, not per person, and anyone who has read the chip can compute it (docs/circuits/envelope.md, *Nullifier*).

The step links (`c_A`, `c_B`) are checked inside the kernels, not by the verifier.

There's no hash policy. Documents signed or hashed with SHA-1 are accepted like any other, as ICAO 9303 allows (keeping those issuers' keys sound is ICAO's and the issuers' responsibility), and the proof doesn't say which hashes a document used.

The verifier doesn't check `viewer`: it's the receiver's key, which only the sender and the receiver agreed on, and the circuit already rejects `(0, 0)`. A verifier may reject a viewer key it has already seen, as hygiene against reuse, but it isn't required.

Then the envelope (`E`, `wrapped`, `ciphertext`) is stored with the transfer.

## Receiver

The viewer is the transfer's receiver. Before the transfer, the receiver gives the sender (the document holder) a fresh Grumpkin key, off-chain; a new one every time, because the key is public and a reused key links the transfers it appears in. Once the transfer is accepted, the receiver:

1. checks that the proof's `viewer` is the key it issued for this transfer;
2. opens the envelope with `eid_envelope::open(envelope, context, 0, secret)` (`rust/eid-envelope`) and that key's secret.

The circuit proves the envelope is sealed to the public `viewer`, so a receiver whose key matches always gets the DG1 the issuer signed. The receiver keeps the secret of every key it has issued.

## What the verifier learns

Only the public outputs: the registry root, the date, the context, the viewer key, the envelope, and the scope and nullifier. With a scope, proofs of the same document in that scope are linkable by design; across scopes, or with scope 0, they aren't. It doesn't learn which step circuits were used, so not the signature schemes, hashes, key sizes or buckets. Neither does it learn anything about the holder or the document: the salts (`c_A`, `c_B`) never leave the proof.

## Keys to publish per release

- the hiding kernel's verification key: `bb write_vk --scheme chonk --circuit_kind hiding` on `kernel_hiding`;
- the key tree root from `noir/circuits/vk-tree.json`.

`rust/eid-circuits` embeds both (`KernelHiding::VK_BYTES`, `vk_tree_root()`). `noir_zk_backend::fold::verify::<KernelHiding>` checks the proof and the key tree root, and decodes the outputs above into the generated `kernel_hiding::Outputs`.

Both change when a circuit or the toolchain (nargo, bb) changes.
