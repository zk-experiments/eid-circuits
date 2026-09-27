# eid-circuits

Noir circuits that prove, for an encrypted identity document (passport, ID card, residence permit), that it was issued under a registered country signing CA (CSCA) and was valid on a given date. The document data (DG1, the MRZ) is encrypted to a set of viewer keys, and the encryption is proven correct. The CSCA registry, its Poseidon2 commitment and the Noir library that checks it come from [zk-experiments/csca-registry](https://github.com/zk-experiments/csca-registry).

All circuit code here is written for this repository and grouped by signature type. Every circuit and library has a specification README written for review; start with [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/AUDIT.md](docs/AUDIT.md).

## Layout

| path | contents | status |
|---|---|---|
| `noir/lib/hash` | SHA-1/224/256/384/512 over variable-length input, `Digest` trait | done |
| `noir/lib/rsa` | RSASSA-PKCS1-v1_5 and RSASSA-PSS over noir-bignum | done |
| `noir/lib/ecdsa` | ECDSA on P-256/384/521, brainpoolP256/384/512r1 | done |
| `noir/lib/envelope` | Grumpkin ECDH per viewer, key wrap, Poseidon2 duplex encryption | done |
| `noir/lib/der` | constrained DER reading: `TBSCertificate`s, public keys, CMS signed attributes, LDS security objects | done |
| `noir/lib/steps` | shared step checks (DSC, SOD, envelope) and the commitments linking them | done |
| `noir/circuits/dsc/…` | DSC step: 124 circuits (31 CSCA signing configurations × 4 size buckets) | done |
| `noir/circuits/sod/…` | SOD step: 124 circuits (31 DSC signing configurations × 4 size buckets) | done |
| `noir/circuits/envelope/…` | envelope step: 48 circuits (16 hash pairs × 3 eContent buckets) | done |
| `noir/bench` | one benchmark circuit per signature group and hash; gates and opcodes in CI | done |
| `noir/vendor/sha512` | `noir-lang/sha512` at a pinned commit | vendored |
| `noir/vendor/noir_bigcurve` | `noir-lang/noir_bigcurve` v0.14.0 plus generated curves | vendored |
| `rust/eid-vectors` | test-vector generator (real certificates from master lists, synthetic documents) | done |
| `rust/eid-envelope` | envelope encryption for provers (`seal`) and viewers (`open`) | done |
| `rust/eid-prover` | from the NFC read (EF.SOD, DG1): circuit selection, native pre-checks, and the inputs of all three steps | done (folding next) |

## Build and test

```sh
nargo test                     # every Noir package in the workspace (nargo 1.0.0-beta.22)
cd rust && cargo test          # Rust tools, incl. the check that generated files are current
mise run circuit-sizes         # refresh docs/data/circuit-sizes.json (CI checks it for the samples)
scripts/measure-proving.sh "<machine>"   # bb prove time and memory for the DSC samples (docs/data)
```

Generated files (Noir vectors, curves, circuits, root `Nargo.toml`, `docs/COSTS.md`) come from `rust/eid-vectors`; see its `--help`. Per-country proving cost estimates for mobile are in [docs/COSTS.md](docs/COSTS.md).
