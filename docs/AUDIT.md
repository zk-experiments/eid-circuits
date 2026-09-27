# Audit notes

## Dependencies

| dependency | pin | license | used for |
|---|---|---|---|
| `noir-lang/noir-bignum` | tag `v0.10.0` | Apache-2.0 | RSA modular arithmetic |
| `zac-williamson/sha1` | tag `v0.11` | Apache-2.0 | SHA-1 |
| `noir-lang/sha256` | tag `v0.3.0` | **none in repository** | SHA-224/256 |
| `noir-lang/sha512` | commit `e92ffb4`, vendored in `noir/vendor/sha512` | Apache-2.0 | SHA-384/512 |
| `noir-lang/noir_bigcurve` | tag `v0.14.0`, vendored in `noir/vendor/noir_bigcurve` with four generated curve files added | **none in repository** | ECDSA curve arithmetic |
| `noir-lang/poseidon` | tag `v0.3.0` (via csca_registry) | Apache-2.0 | Poseidon2 |
| `zk-experiments/csca-registry` | tag `v0.3.0` | MIT | registry leaf/Merkle checks (Noir), certificate parsing for vectors (Rust) |

`noir-lang/sha256` and `noir-lang/noir_bigcurve` have no LICENSE file. The project owner accepted using them pinned; the gap stays open here until upstream adds a license.

## Upstream issues found

These are reported in this file and don't affect our soundness.

- **noir_bigcurve's `derive_curve_impl` can't be used from another crate.** It expands to references to private modules. That's why the library is vendored and our curves are defined inside it (see its `PROVENANCE.md`).
- **noir_bigcurve's `hash_to_curve` seed packing is broken.** `poseidon_hash_bytes` never writes the packed seed into the array it hashes, so every seed hashes to the same value. We derive offset generators independently (see `noir/lib/ecdsa`).
- **csca_registry's exclusion check rejects an empty revocation tree.** It says an "empty revocation tree needs no exclusion witness" but gives no alternative, so with zero revocations every DSC step would be unprovable. The current registry has revocations; the fix belongs in csca_registry (accept `upper.index = 0`, `upper_leaf = 0` when the tree is empty).
- **`pso-poseidon`'s `hash` differed from `noir-lang/poseidon` for input lengths that are a multiple of 3.** Fixed upstream with `hash_noir` (psonet/pso-poseidon#8); csca-registry uses it.

## Assumptions every circuit relies on

1. **Registry root.** It must be a public input checked against the published root; `csca_registry` only proves consistency with it. The revocation tree must be canonical (see the csca_registry README).
2. **Key binding.** RSA and ECDSA libraries check a signature under the key they are given. The circuit must source that key from a registry leaf (CSCA) or from the signed DSC certificate (DSC).
3. **Barrett parameters.** They are prover-supplied and only used in unconstrained code; they affect completeness, not soundness (see `noir/lib/rsa`).
4. **Hash inputs.** Hash inputs are the first `len` bytes of fixed buffers, and trailing bytes are ignored by construction. Every circuit must derive `len` from constrained data, such as the DER length of the element being hashed.

## Known limitations

- **SHA-1 is accepted** where issuers sign with it (see `noir/lib/hash`).
- **PKCS#1 v1.5 DigestInfo** must include the NULL parameter.
- **RSA-PSS** requires MGF1 with the same hash as the message.
- **RSA exponents** must be odd and below `2^E_BITS`.
- **Curves.** ECDSA covers P-256/384/521 and brainpoolP256/384/512r1. Signatures on other curves (P-192, P-224, the smaller brainpool curves and the twisted t1 variants) are rejected. The registry reports them as unsupported, and none occur among verified CSCA signatures in the fixtures.

## How test vectors are produced

`rust/eid-vectors` does the following:
1. It loads the DE and IT master lists from csca-registry's fixtures with csca-registry's own verifier (`extract`).
2. It stores each chosen certificate with its issuer under `rust/eid-vectors/fixtures`.
3. It re-verifies every case with RustCrypto before writing `vectors.nr`.

CI regenerates the vectors and fails if the committed file differs.
