# Benchmarks

One bin circuit per signature group and hash, each doing a single operation on private inputs: a signature check from a digest, or a hash over up to 2048 bytes. They're plain circuits (no databus), measured like every bin in the workspace by `.github/scripts/circuit_sizes.py`: ACIR opcodes and `bb gates --scheme chonk`, the Mega arithmetisation the folded proof uses, so the numbers compare with the step circuits. The results live in `docs/data/circuit-sizes.json` (refreshed locally with `mise run circuit-sizes`), and on a pull request that touches circuits CI comments the change against the base.

Measured with nargo 1.0.0-rc.3 and bb 7.0.0-nightly.20260927:

| circuit | ACIR opcodes | gates |
|---|---:|---:|
| `rsa_pkcs1v15/2048_sha256` | 7,190 | 44,355 |
| `rsa_pkcs1v15/3072_sha256` | 10,373 | 74,409 |
| `rsa_pkcs1v15/4096_sha256` | 13,964 | 116,709 |
| `rsa_pkcs1v15/6144_sha256` | 20,699 | 223,170 |
| `rsa_pss/3072_sha256_s32` | 11,661 | 133,442 |
| `rsa_pss/4096_sha256_s32` | 15,644 | 192,819 |
| `rsa_pss/4096_sha512_s64` | 127,374 | 286,600 |
| `ecdsa/p256_sha256` | 30,131 | 93,345 |
| `ecdsa/p384_sha256` | 60,840 | 203,904 |
| `ecdsa/p521_sha256` | 105,308 | 372,640 |
| `ecdsa/bp256_sha256` | 30,131 | 93,345 |
| `ecdsa/bp384_sha256` | 60,840 | 203,904 |
| `ecdsa/bp512_sha256` | 102,387 | 363,153 |
| `hash/sha1_2048` | 200,018 | 290,413 |
| `hash/sha256_2048` | 11,988 | 152,895 |
| `hash/sha384_2048` | 234,617 | 351,530 |
| `hash/sha512_2048` | 234,633 | 351,538 |

Against nargo 1.0.0-beta.22 with bb 5.0.0-nightly.20260522 (`bb gates -t noir-recursive`), bb 7 lowers gates by 0.4–1.6% on the RSA and ECDSA circuits, and by 23–32% on the ones hashing with SHA-1, SHA-384, SHA-512 or PSS over SHA-512, which are lookup-heavy. Opcodes are within 0.5% of before (the compiler, not the backend, sets them).

Reading the table:
- Hashing a certificate's TBS can cost more than verifying its signature: SHA-256 over 2 KiB is 152,895 gates, an RSA-2048 check 44,355. SHA-256 is the cheapest hash, because it uses Noir's built-in compression function; SHA-1 and SHA-384/512 are implemented with ordinary constraints. SHA-1 uses `zac-williamson/sha1` (see `noir/lib/hash`), chosen over an in-house version by an earlier benchmark. Step circuits should size message buffers to the largest real input, not a round number.
- Curves with the same limb layout cost the same: P-256 and brainpoolP256r1, P-384 and brainpoolP384r1.
