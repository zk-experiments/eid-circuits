# Benchmarks

One bin circuit per signature group and hash, each doing a single operation on private inputs: a signature check from a digest, or a hash over up to 2048 bytes. CI measures every bin circuit in the workspace (`.github/scripts/circuit_sizes.py`: ACIR opcodes and `bb gates -t noir-recursive`) and comments the change against the PR base.

Measured with nargo 1.0.0-beta.22 and bb 5.0.0-nightly.20260522:

| circuit | ACIR opcodes | gates |
|---|---:|---:|
| `rsa_pkcs1v15/2048_sha256` | 7,190 | 44,677 |
| `rsa_pkcs1v15/3072_sha256` | 10,373 | 74,870 |
| `rsa_pkcs1v15/4096_sha256` | 13,900 | 117,328 |
| `rsa_pkcs1v15/6144_sha256` | 20,619 | 224,086 |
| `rsa_pss/3072_sha256_s32` | 11,661 | 134,166 |
| `rsa_pss/4096_sha256_s32` | 15,580 | 193,792 |
| `rsa_pss/4096_sha512_s64` | 127,310 | 373,356 |
| `ecdsa/p256_sha256` | 30,131 | 94,828 |
| `ecdsa/p384_sha256` | 60,840 | 206,654 |
| `ecdsa/p521_sha256` | 104,786 | 376,063 |
| `ecdsa/bp256_sha256` | 30,131 | 94,828 |
| `ecdsa/bp384_sha256` | 60,840 | 206,654 |
| `ecdsa/bp512_sha256` | 101,873 | 366,526 |
| `hash/sha1_2048` | 296,750 | 457,422 |
| `hash/sha256_2048` | 11,988 | 153,754 |
| `hash/sha384_2048` | 234,617 | 514,909 |
| `hash/sha512_2048` | 234,633 | 514,941 |

Reading the table:
- Hashing a certificate's TBS can cost more than verifying its signature. SHA-256 is cheapest, because it uses Noir's built-in compression function; SHA-1 and SHA-384/512 are implemented with ordinary constraints. Step circuits should size message buffers to the largest real input, not a round number.
- Curves with the same limb layout cost the same: P-256 and brainpoolP256r1, P-384 and brainpoolP384r1.
