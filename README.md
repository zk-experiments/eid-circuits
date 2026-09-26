# eid-circuits

Noir circuits that prove, for an encrypted identity document (passport, ID card, residence permit), that it was issued under a registered country signing CA (CSCA) and was valid on a given date. The document data (DG1 and DG11) is encrypted to a set of viewer keys, and the encryption is proven correct. The CSCA registry, its Poseidon2 commitment and the Noir library that checks it come from [zk-experiments/csca-registry](https://github.com/zk-experiments/csca-registry).

All circuit code here is written for this repository and grouped by signature type. Every circuit and library has a specification README written for review; start with [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/AUDIT.md](docs/AUDIT.md).

## Layout

| path | contents | status |
|---|---|---|
| `noir/lib/hash` | SHA-1 (own), SHA-224/256/384/512, `Digest` trait | done |
| `noir/lib/rsa` | RSASSA-PKCS1-v1_5 and RSASSA-PSS over noir-bignum | done |
| `noir/lib/ecdsa` | ECDSA on P-256/384/521, brainpoolP256/384/512r1 | planned |
| `noir/lib/envelope` | Grumpkin ECDH per viewer, key wrap, Poseidon2 duplex encryption | planned |
| `noir/circuits/…` | DSC, SOD and envelope steps per signature type; aggregation | planned |
| `noir/vendor/sha512` | `noir-lang/sha512` at a pinned commit | vendored |
| `rust/eid-vectors` | test-vector generator (real certificates from master lists) | done |

## Build and test

```sh
nargo test                     # every Noir package in the workspace (nargo 1.0.0-beta.22)
cd rust && cargo test          # Rust tools
cd rust && cargo run -p eid-vectors -- rsa --check   # generated RSA vectors are current
```

`rust/eid-vectors` depends on csca-registry over SSH (`ssh://git@github.com/zk-experiments/csca-registry.git`, tag `v0.3.0`), so a local checkout needs read access to that repository.
