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
| `zk-experiments/csca-registry` | tag `v0.3.1` | MIT | registry leaf/Merkle checks (Noir), certificate parsing for vectors (Rust) |

Rust crates outside the circuits:

| crate | used by | used for |
|---|---|---|
| `pso-poseidon` 0.5, `ark-grumpkin`/`ark-bn254` 0.6 | `rust/eid-envelope` | the envelope encryption (Poseidon2, Grumpkin) for provers and viewers |
| `rsa` 0.9, `rand_chacha` 0.3 | `rust/eid-vectors` | signing synthetic test documents with published mock keys (RUSTSEC-2023-0071 doesn't apply: there are no secret keys) |

`noir-lang/sha256` and `noir-lang/noir_bigcurve` have no LICENSE file. The project owner accepted using them pinned; the gap stays open here until upstream adds a license.

## Upstream issues found

These are reported in this file and don't affect our soundness.

- **noir_bigcurve's `derive_curve_impl` can't be used from another crate.** It expands to references to private modules. That's why the library is vendored and our curves are defined inside it (see its `PROVENANCE.md`).
- **noir_bigcurve's `hash_to_curve` seed packing is broken.** `poseidon_hash_bytes` never writes the packed seed into the array it hashes, so every seed hashes to the same value. We derive offset generators independently (see `noir/lib/ecdsa`).
- **nargo warns that noir_bigcurve's MSM hint is under-constrained** (`bug: Brillig function call isn't properly covered by a manual constraint`, `noir/vendor/noir_bigcurve/src/ops/msm.nr:215`, in every ECDSA DSC and SOD circuit). We reviewed it: it's a false positive. `evaluate_linear_expression` calls the unconstrained `compute_linear_expression_transcript`, keeps only its transcript (`.1`), and replays the whole MSM in constrained code. Every transcript entry `(lambda, x3, y3)` is range-checked and pinned by `double_with_hint` / `incomplete_add_with_hint`: the slope equation and both output-coordinate equations, plus `x1 != x2` for additions. The replay reads each of the `S·M + 4S + 9M + A − 3` entries exactly once. The only unconstrained outputs are the hint's discarded result point (`.0`), which nothing uses. RSA, envelope and kernel circuits don't trigger the warning.
- **csca_registry's exclusion check rejected an empty revocation tree**, which would have made every DSC step unprovable with zero revocations. Fixed in csca-registry v0.3.1 (zk-experiments/csca-registry#3): without a lower bound, slot 0 may hold the zero leaf, which a canonical tree only has when it is empty.
- **`pso-poseidon`'s `hash` differed from `noir-lang/poseidon` for input lengths that are a multiple of 3.** Fixed upstream with `hash_noir` (psonet/pso-poseidon#8); csca-registry uses it.

## Assumptions every circuit relies on

1. **Registry root.** It must be a public input checked against the published root; `csca_registry` only proves consistency with it. The revocation tree must be canonical (see the csca_registry README).
2. **Key binding.** RSA and ECDSA libraries check a signature under the key they are given. The circuit must source that key from a registry leaf (CSCA) or from the signed DSC certificate (DSC).
3. **Barrett parameters.** They are prover-supplied and only used in unconstrained code; they affect completeness, not soundness (see `noir/lib/rsa`).
4. **Hash inputs.** Hash inputs are the first `len` bytes of fixed buffers, and trailing bytes are ignored by construction. Every circuit must derive `len` from constrained data, such as the DER length of the element being hashed. Every buffer is also asserted zero past its length, so commitments over whole buffers have one preimage per value.
5. **Step links and variants.** The kernels fold the three steps and check, in-circuit, that each step's verification key is in the key tree under its role and that A's `c_A` reappears in B and B's `c_B` in C (docs/FOLDING.md). The verifier must pin the hiding kernel's key and the key tree root, or any circuit could be folded.
6. **Verifier-side inputs.** The verifier must check, against the proof's public outputs, that:
   - `root` is a published registry root it still accepts;
   - `date` is the current date;
   - `context` identifies the transfer;
   - the viewer keys are registered Grumpkin keys (the circuit accepts any point).
7. **Prover randomness.** Soundness doesn't depend on it, but privacy does:
   - the salts must be fresh, or `c_A`/`c_B` link bundles;
   - `e` and `K` must be fresh and uniform, or envelopes share a keystream.

   The circuit only rejects `e = 0`.

8. **Toolchain coupling.** The kernels hard-code bb 7.0.0-nightly.20260927's recursion proof types (OINK 1, HN 2, HN_FINAL 7) and 151-field keys; Chonk is Aztec's client IVC, not a documented public API. A bb upgrade needs `eid_kernel` checked against it and the key tree rebuilt.
9. **Chonk soundness and zero knowledge** are barretenberg's. The kernels only add the application checks (key tree, links, public outputs).

## Known limitations

- **SHA-1 is accepted** where issuers sign with it (see `noir/lib/hash`).
- **PKCS#1 v1.5 DigestInfo** must include the NULL parameter.
- **RSA-PSS** requires MGF1 with the same hash as the message.
- **RSA exponents** must be odd and below `2^E_BITS`.
- **Curves.** ECDSA covers P-256/384/521 and brainpoolP256/384/512r1. Signatures on other curves (P-192, P-224, the smaller brainpool curves and the twisted t1 variants) are rejected. The registry reports them as unsupported, and none occur among verified CSCA signatures in the fixtures.
- **DSC keys with explicit EC parameters** are bound by `p`, `a` and `b`. The generator, order and cofactor aren't compared; the ECDSA library checks the point is on the circuit's curve (see docs/circuits/sod.md). Coefficients are compared as numbers, because at least one issuer writes them with a leading `0x00`.
- **Signed attributes:** at most 8, in at most 256 bytes. Only `messageDigest` is interpreted; `contentType` and `signingTime` are ignored.
- **LDS security object:** at most 16 data groups and 1536 bytes. Only DG1 is interpreted and encrypted; DG11 was dropped for cost (docs/circuits/envelope.md).
- **MRZ dates** are read as 20YY in UTC, and check digits aren't verified (the data group is signed).
- **The DSC's own validity period isn't checked.** Documents outlive their DSC's signing period, as ICAO 9303 intends.
- **Circuit variants stay private** because every document is folded under the same hiding kernel key; only a single SHA-1 flag is public. Every proof is the same size (43,968 bytes for all four synthetic documents, whose variants all differ). Proving time differs by variant, so it must not leak outside the proof (for example through submission timing).
- **SOD configurations mirror the CSCA configurations.** Real DSC statistics may add or remove variants.

## How test vectors are produced

`rust/eid-vectors` does the following:
1. It loads the DE and IT master lists from csca-registry's fixtures with csca-registry's own verifier (`extract`).
2. It stores each chosen certificate with its issuer under `rust/eid-vectors/fixtures`.
3. It re-verifies every case with RustCrypto before writing `vectors.nr`.

CI regenerates the vectors and fails if the committed file differs.

The SOD and envelope steps can't use real documents: SODs and data groups are personal data. `rust/eid-vectors/src/mock.rs` builds synthetic ones:
- a DSC `TBSCertificate` for each configuration, with a deterministic key (seeded RSA key generation; ECDSA over our own curve arithmetic, with deterministic nonces);
- signed attributes, an LDS security object (v0 or v1), and DG1 from the ICAO 9303 specimen MRZs (TD1/TD2/TD3, check digits reproduced).

Every synthetic signature is verified with csca-registry's RustCrypto verifier before it is written, and every key read is also tested on the 33 real certificates. The mock keys are public, so these documents prove nothing about real issuers; they only exercise the circuits.
