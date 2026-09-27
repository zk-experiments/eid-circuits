# Architecture

## Statement

For a public registry root `R`, date `D`, viewer keys `V₁…Vₙ` and ciphertext `C`, the full proof asserts that there is an eMRTD for which all of the following hold:

1. The CSCA key `K_csca` is a leaf under `R`, and that leaf's validity period covers the DSC's `notBefore` (see *Date policy*). The leaf's country equals the document's issuing state.
2. `K_csca` signed the DSC certificate, and the DSC's serial is not revoked under `K_csca` in `R`'s revocation tree.
3. The DSC key signed the SOD's signed attributes. Their `messageDigest` is the hash of the SOD's eContent (the LDS security object).
4. The eContent lists the hashes of DG1 and DG11, and they match the DG1 and DG11 the prover holds.
5. The document's expiry date (from DG1) is on or after `D`.
6. `C` is DG1 ‖ DG11 encrypted under a fresh data key, and that key is wrapped to each `Vᵢ` in the proof's outputs.

## Proof pipeline

A single circuit covering RSA-4096 or brainpool signature checks, ASN.1 parsing and encryption would be very large, and it would have to exist for every combination of signature types. The statement is therefore split into steps, each a separate circuit per signature type. The steps are linked by salted Poseidon2 commitments (`H(salt, values…)`), which reveal nothing and bind the private values passed between steps:

| step | circuits | checks | public | commits to |
|---|---|---|---|---|
| A · DSC | `circuits/dsc/<scheme>` | 1, 2 | `R`, `D` | country, DSC key, DSC serial |
| B · SOD | `circuits/sod/<scheme>` | 3, except the eContent hash (DSC key from A's `TBSCertificate`) | — | country, `messageDigest` |
| C · envelope | `circuits/envelope/<econtent hash>_<dg hash>` | eContent hash = `messageDigest`, 4, 5, 6 | `D`, `Vᵢ`, ephemeral key, wrapped keys, `C` | — |
| D · aggregate | `circuits/aggregate` | verifies A, B and C recursively, and checks their commitments chain | everything above | — |

`<scheme>` is the signature group: `rsa_pkcs1v15/<bits>_<hash>`, `rsa_pss/<bits>_<hash>_s<salt>`, `ecdsa/<curve>_<hash>`. Each circuit is a thin generated binary over the shared library for its signature type (`noir/lib/rsa`, `noir/lib/ecdsa`) and `noir/lib/steps`. Only the parameters differ between members of a group.

### Decisions

- **Size buckets.** Certificate and SOD buffers come in fixed buckets (700, 1000, 1200, 1600 bytes for the DSC `TBSCertificate`), and the prover uses the smallest that fits. Hashing cost follows the bucket.
- **Hash ids are public.** Every step outputs the hash algorithm it used, and the aggregation exposes the weakest one. A verifier can then refuse SHA-1-derived proofs by policy, without separate circuits.
- **SHA-1 is supported where issuers use it.** Circuits are generated only for configurations in the registry data; four of the 31 DSC configurations use SHA-1 (see docs/COSTS.md).

Status: steps A (DSC), B (SOD) and C (envelope) are built. Their specifications are [docs/circuits/dsc.md](circuits/dsc.md), [docs/circuits/sod.md](circuits/sod.md) and [docs/circuits/envelope.md](circuits/envelope.md); step A's costs are in [docs/COSTS.md](COSTS.md). Step D (aggregation) is next.

## Libraries

| library | used by | spec |
|---|---|---|
| `csca_registry` (from csca-registry, git tag) | A | [csca-registry/noir/csca_registry](https://github.com/zk-experiments/csca-registry/tree/main/noir/csca_registry) |
| `eid_der` | A, B, C | [noir/lib/der](../noir/lib/der/README.md) |
| `eid_steps` | A, B, C | [noir/lib/steps](../noir/lib/steps/README.md) |
| `eid_hash` | A, B, C | [noir/lib/hash](../noir/lib/hash/README.md) |
| `eid_rsa` | A, B | [noir/lib/rsa](../noir/lib/rsa/README.md) |
| `eid_ecdsa` | A, B | [noir/lib/ecdsa](../noir/lib/ecdsa/README.md) |
| `eid_envelope` | C | [noir/lib/envelope](../noir/lib/envelope/README.md); Rust: [rust/eid-envelope](../rust/eid-envelope) |

## Date policy

Decided: the **ICAO chain model**. `csca_registry::verify_key` checks the CSCA leaf's validity period against the DSC's `notBefore`, meaning the CSCA had to be valid when it issued the DSC. The document can then stay valid after its CSCA expires, as ICAO 9303 intends. The document's own expiry (DG1) is checked against the proof date `D`. The DSC's `notBefore` has to come from the signed DSC certificate (its `TBSCertificate` validity), not from a free input.

## Encryption

KEM/DEM:
1. The prover picks an ephemeral Grumpkin key `e` and publishes `E = e·G`.
2. For each viewer, it computes `kᵢ = Poseidon2(WRAP, e·Vᵢ, i)` and wraps a random data key `K` as `K + kᵢ`.
3. It encrypts DG1 ‖ DG11 under `K` with a Poseidon2 duplex, as fixed-length field elements so the length of DG11 is hidden.

The full construction is in [noir/lib/envelope](../noir/lib/envelope/README.md).

No AEAD tag is proven: the proof itself binds `C` to a verified plaintext, and a viewer checks integrity against the on-chain proof. A Rust implementation of the same construction does encryption for provers and decryption for viewers.

## Cost

Per-operation gate counts for every signature group are measured in CI and listed in [noir/bench/README.md](../noir/bench/README.md).
