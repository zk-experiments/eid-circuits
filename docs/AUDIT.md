# Audit notes

## Dependencies

| dependency | pin | license | used for |
|---|---|---|---|
| `noir-lang/noir-bignum` | tag `v0.10.0` | Apache-2.0 | RSA modular arithmetic |
| `noir-lang/sha256` | tag `v0.3.0` | **none in repository** | SHA-224/256 |
| `noir-lang/sha512` | commit `e92ffb4`, vendored in `noir/vendor/sha512` | Apache-2.0 | SHA-384/512 |
| `noir-lang/noir_bigcurve` | tag `v0.14.0` (planned) | **none in repository** | ECDSA curve arithmetic |
| `noir-lang/poseidon` | tag `v0.3.0` (via csca_registry) | Apache-2.0 | Poseidon2 |
| `zk-experiments/csca-registry` | tag `v0.3.0` | MIT | registry leaf/Merkle checks (Noir), certificate parsing for vectors (Rust) |

`noir-lang/sha256` and `noir-lang/noir_bigcurve` have no LICENSE file. The project owner accepted using them pinned; the gap stays open here until upstream adds a license.

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

## How test vectors are produced

`rust/eid-vectors` does the following:
1. It loads the DE and IT master lists from csca-registry's fixtures with csca-registry's own verifier (`extract`).
2. It stores each chosen certificate with its issuer under `rust/eid-vectors/fixtures`.
3. It re-verifies every case with RustCrypto before writing `vectors.nr`.

CI regenerates the vectors and fails if the committed file differs.
