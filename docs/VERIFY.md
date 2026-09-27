# Verifying a document proof

A document proof is one Chonk proof: the three steps folded with the kernels described in [FOLDING.md](FOLDING.md). It is verified natively (`bb verify --scheme chonk`, about 20 ms) against the hiding kernel's verification key. That's the same key for every document, whatever signature schemes and sizes it used. There is no Solidity verifier for Chonk; verification is meant for a chain precompile.

## Bundle

A transfer carrying a document submits the Chonk proof and its public outputs (`eid_kernel::PublicOutputs`):

| output | meaning |
|---|---|
| `registry_root` | csca-registry root the CSCA and revocation checks used |
| `vk_tree_root` | root of the key tree every step and kernel was checked against |
| `uses_sha1` | 1 when any signature or hash on the path used SHA-1 |
| `date`, `context` | proof date and the context the envelope is bound to |
| `viewers` | four Grumpkin viewer keys; `(0, 0)` marks an empty slot |
| `ephemeral`, `wrapped`, `ciphertext` | the envelope: `E`, four wrapped data keys, six ciphertext fields |

## Checks

The verifier accepts the bundle only if all of these hold:

1. **The proof verifies** under the pinned hiding kernel key.
2. **`vk_tree_root` is the published key tree root** (`noir/circuits/vk-tree.json` for the release in use). The tree fixes which circuits may be used, so it must be pinned like the hiding kernel key.
3. **`registry_root` is a published registry root** the verifier still accepts: the current one, or one within a short window, so revocations take effect.
4. **`date` is now**, within the verifier's tolerance. The envelope step proves the document hasn't expired at `date`.
5. **`context` identifies this transfer.** It's chosen before proving (for example `H(chain id, contract, sender, nonce)` or the transfer's note commitment; it can't be the transaction hash, which depends on the proof). The envelope is encrypted under it, so a bundle copied to another transfer fails this check, and viewers need `context` to decrypt.
6. **`viewers` are registered viewer keys**, or `(0, 0)` for an unused slot. The circuit accepts any point.
7. **Hash policy.** For example, reject `uses_sha1 = 1`.

The step links (`c_A`, `c_B`) are checked inside the kernels, not by the verifier.

Then the envelope (`E`, `wrapped`, `ciphertext`) is stored with the transfer. A viewer in slot `i` opens it with `eid_envelope::open(envelope, context, i, secret)` (`rust/eid-envelope`).

## What the verifier learns

Only the public outputs: the registry root, the date, the context, the viewer keys, the envelope and whether SHA-1 was used. It doesn't learn which step circuits were used, so not the signature schemes, key sizes or buckets. `uses_sha1` is the exception, and only as a single bit. Neither does it learn anything about the holder or the document: the salts (`c_A`, `c_B`) never leave the proof.

## Keys to publish per release

- the hiding kernel's verification key: `bb write_vk --scheme chonk --use_zk_flavor` on `kernel_hiding`;
- the key tree root from `noir/circuits/vk-tree.json`.

Both change when a circuit or the toolchain (nargo, bb) changes.
