# Architecture

## Statement

For a public registry root `R`, date `D`, viewer keys `V₁…Vₙ` and ciphertext `C`, the full proof asserts that there is an eMRTD for which all of the following hold:

1. The CSCA key `K_csca` is a leaf under `R`, and that leaf's validity period covers the date the circuit checks (see *Date policy*). The leaf's country equals the document's issuing state.
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
| B · SOD | `circuits/sod/<scheme>` | 3 (DSC key from A) | — | country, eContent digest input |
| C · envelope | `circuits/envelope/<hash>` | 4, 5, 6 | `D`, `Vᵢ`, ephemeral key, wrapped keys, `C` | — |
| D · aggregate | `circuits/aggregate` | verifies A, B and C recursively, and checks their commitments chain | everything above | — |

`<scheme>` is the signature group: `rsa_pkcs1v15/<bits>/<hash>`, `rsa_pss/<bits>/<hash>/<salt>`, `ecdsa/<curve>/<hash>`. Each group is a thin binary over the shared library for that signature type (`noir/lib/rsa`, `noir/lib/ecdsa`). Only the parameters differ between members of a group.

## Libraries

| library | used by | spec |
|---|---|---|
| `csca_registry` (from csca-registry, git tag) | A | [csca-registry/noir/csca_registry](https://github.com/zk-experiments/csca-registry/tree/main/noir/csca_registry) |
| `eid_hash` | A, B, C | [noir/lib/hash](../noir/lib/hash/README.md) |
| `eid_rsa` | A, B | [noir/lib/rsa](../noir/lib/rsa/README.md) |
| `eid_ecdsa` | A, B | planned |
| `eid_envelope` | C | planned |

## Date policy

This is still open and needs a decision before step A is written. There are two options for which date `csca_registry::verify_key` checks against the CSCA period:

- **`D` (shell model):** the CSCA must still be valid when the proof is made.
- **The DSC's `notBefore` (ICAO chain model):** the CSCA had to be valid when it issued the DSC. The document can stay valid after the CSCA expires, which is what ICAO 9303 intends.

Document expiry is checked against `D` either way.

## Encryption

KEM/DEM:
1. The prover picks an ephemeral Grumpkin key `e` and publishes `E = e·G`.
2. For each viewer, it computes `kᵢ = Poseidon2(e·Vᵢ, …)` and wraps a random data key `K` as `K + Poseidon2(kᵢ, …)`.
3. It encrypts DG1 ‖ DG11 under `K` with a Poseidon2 duplex, as fixed-length field elements so the length of DG11 is hidden.

No AEAD tag is proven: the proof itself binds `C` to a verified plaintext, and a viewer checks integrity against the on-chain proof. A Rust implementation of the same construction does encryption for provers and decryption for viewers.
