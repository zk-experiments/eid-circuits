# Verifying a document proof

A document proof is three separate proofs, one per step, checked by the verifier (the chain). There is no aggregation proof: recursively verifying even one step proof costs about 705k gates, so aggregating three can't be done on a phone within the 2 GiB cap (see ARCHITECTURE.md).

## Bundle

A transfer carrying a document submits:

| part | from | values |
|---|---|---|
| DSC proof | step A | public input `root`; outputs `c_A`, `hash_id_A` |
| SOD proof | step B | outputs `c_A`, `c_B`, `hash_id_B` |
| envelope proof | step C | public inputs `date`, `context`, `viewers[4]`; outputs `c_B`, `econtent_hash_id`, `dg_hash_id`, `envelope` (`E`, `wrapped[4]`, `ciphertext[6]`) |
| circuit ids | prover | which circuit each proof is for (see *Verification keys*) |

## Checks

The verifier accepts the bundle only if all of these hold:

1. **Each proof verifies** under the verification key of the circuit it names, and that circuit is in the allowed set.
2. **The steps are linked:** A's `c_A` equals B's `c_A`, and B's `c_B` equals C's `c_B`. The commitments are salted, so they reveal nothing, but they bind:
   - B to the DSC certificate A verified;
   - C to the `messageDigest` the DSC signed;
   - all three to one country.
3. **`root` is a published registry root** that the verifier still accepts: the current one, or one within a short window, so revocations take effect.
4. **`date` is now**, within the verifier's tolerance. The envelope step proves the document hasn't expired at `date`.
5. **`context` identifies this transfer.** It's chosen before proving (for example `H(chain id, contract, sender, nonce)` or the transfer's note commitment; it can't be the transaction hash, which depends on the proof). The envelope is encrypted under it, so a bundle copied to another transfer fails this check, and viewers need `context` to decrypt.
6. **`viewers` are registered viewer keys**, or `(0, 0)` for an unused slot. The circuit accepts any point.
7. **Hash policy.** For example, reject bundles where any hash id is 1 (SHA-1).

Then the envelope (`E`, `wrapped`, `ciphertext`) is stored with the transfer. A viewer in slot `i` opens it with `eid_envelope::open(envelope, context, i, secret)` (`rust/eid-envelope`).

## What the verifier learns

- **The circuits used.** Each verification key identifies a signature configuration and size bucket, which narrows down the issuing country: the CSCA and DSC schemes, and the eContent and data group hashes. Only an aggregation proof over a set of allowed keys would hide this.
- **Nothing about the holder or the document beyond that.** No name, number, dates or country. `c_A` and `c_B` are fresh per bundle (fresh salts), so two bundles for the same document can't be linked unless the holder reuses a cached step A proof (see ARCHITECTURE.md, *Future improvements*).

## Verification keys

There is one circuit per variant: 124 DSC, 124 SOD and 48 envelope circuits. The verifier needs each variant's verification key, or the subset it accepts:
- **EVM:** bb generates one Solidity verifier contract per key (`bb write_solidity_verifier`). Proofs and keys must use the `evm` target (Keccak transcript) instead of `noir-recursive`, which was chosen for recursion.
- **Gates.** The circuits and gate counts are identical for both targets (checked with `bb gates -t evm`), so sizes, costs and the memory cap are unchanged.

Keys only change when a circuit or the toolchain (nargo, bb) changes. They should be published with each release, together with a manifest mapping circuit ids to keys.
