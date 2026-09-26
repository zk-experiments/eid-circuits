# eid_hash

Variable-length digests for eMRTD PKI signatures: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512.

## API

| function | output | implementation |
|---|---|---|
| `sha1_var(msg: [u8; N], len)` | `[u8; 20]` | this crate (`src/sha1.nr`) |
| `sha224_var(msg, len)` / `sha256_var(msg, len)` | `[u8; 28]` / `[u8; 32]` | `noir-lang/sha256` v0.3.0 |
| `sha384_var(msg, len)` / `sha512_var(msg, len)` | `[u8; 48]` / `[u8; 64]` | vendored `noir-lang/sha512` (`noir/vendor/sha512`) |

Each hashes `msg[..len]` and asserts `len ≤ N`. Bytes at index `len` and beyond never affect the result.

`Digest<D>` is implemented by `Sha1`, `Sha224`, `Sha256`, `Sha384` and `Sha512`, so code that is generic over the hash (RSA-PSS, MGF1, ECDSA) can take the algorithm as a type parameter. `SHA1` … `SHA512` (1…5) are the numeric identifiers circuits use.

## SHA-1 construction (`src/sha1.nr`)

FIPS 180-4 §6.1:

1. The message is padded as a `len`-byte message: `0x80`, then zeros, then the 64-bit big-endian bit length, ending at a 64-byte boundary.
2. Every one of `(N + 8) / 64 + 1` blocks is compressed, and the state after block `ceil((len + 9) / 64)` is the result. That is the last block of the padded message.
3. A byte of the input buffer only enters a block when its index is below `len`. Indices past the buffer are clamped at compile time and never used.

## SHA-384/512 wrapper

The vendored library takes a `BoundedVec`. The wrapper copies `msg[..len]` into zeroed storage first, so the library never sees caller bytes past `len`, whatever its own handling of unused capacity.

## Review notes

- **SHA-1 is collision-broken.** It's supported because issuers still sign with it: in the fixtures, CSCA certificates from CN, IT and SM are signed with SHA-1. A circuit that accepts SHA-1 inherits that weakness for those documents.
- **Cost:** every function processes the buffer's full block capacity. Size `N` per circuit to the largest message it must accept.
- **Tests:** `src/tests.nr` checks known answers from Python `hashlib` for all five algorithms. The messages are 0, 3, 55, 56, 64 and 119 bytes: the SHA-1/SHA-256 and SHA-512 padding boundaries, and multi-block messages. Each sits in a 128-byte buffer filled with `0xA5` junk after `len`. Two further tests check that out-of-range lengths are rejected, and one checks `Digest` dispatch.

## Dependencies

- `noir-lang/sha256` v0.3.0: the repository has **no LICENSE file**; tracked in `docs/AUDIT.md`.
- `noir-lang/sha512` at commit `e92ffb4`: Apache-2.0, vendored (see its `PROVENANCE.md`).
