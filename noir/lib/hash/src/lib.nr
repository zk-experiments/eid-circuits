//! Variable-length message digests used by eMRTD PKI signatures.
//!
//! Every function hashes the first `len` bytes of a fixed-capacity array and
//! ignores the rest; callers can pass buffers with arbitrary trailing bytes.
//! SHA-1 comes from `zac-williamson/sha1` v0.11, SHA-224/256 from
//! `noir-lang/sha256` v0.3.0 and SHA-384/512 from the vendored
//! `noir-lang/sha512` (see `noir/vendor/sha512/PROVENANCE.md`).
//! Specification and review notes: README.md.

mod tests;

/// Digest algorithm identifiers used across the circuits.
pub global SHA1: u8 = 1;
pub global SHA224: u8 = 2;
pub global SHA256: u8 = 3;
pub global SHA384: u8 = 4;
pub global SHA512: u8 = 5;

/// SHA-1 (FIPS 180-4) of `msg[..len]`.
pub fn sha1_var<let N: u32>(msg: [u8; N], len: u32) -> [u8; 20] {
    sha1::sha1::sha1_var(bounded(msg, len))
}

/// SHA-224 of `msg[..len]`.
pub fn sha224_var<let N: u32>(msg: [u8; N], len: u32) -> [u8; 28] {
    sha256::sha224_var(msg, len)
}

/// SHA-256 of `msg[..len]`.
pub fn sha256_var<let N: u32>(msg: [u8; N], len: u32) -> [u8; 32] {
    sha256::sha256_var(msg, len)
}

/// SHA-384 of `msg[..len]`.
pub fn sha384_var<let N: u32>(msg: [u8; N], len: u32) -> [u8; 48] {
    sha512::sha384::sha384_var(bounded(msg, len))
}

/// SHA-512 of `msg[..len]`.
pub fn sha512_var<let N: u32>(msg: [u8; N], len: u32) -> [u8; 64] {
    sha512::sha512::sha512_var(bounded(msg, len))
}

/// `msg[..len]` as a `BoundedVec`, with the unused capacity zeroed so the
/// SHA-1 and SHA-384/512 libraries never see caller-controlled bytes past `len`.
fn bounded<let N: u32>(msg: [u8; N], len: u32) -> BoundedVec<u8, N> {
    assert(len <= N, "message length exceeds buffer");
    let mut storage: [u8; N] = [0; N];
    for i in 0..N {
        if i < len {
            storage[i] = msg[i];
        }
    }
    BoundedVec::from_parts(storage, len)
}

/// A digest algorithm with a `D`-byte output, for code generic over the hash
/// (RSA-PSS, MGF1, ECDSA).
pub trait Digest<let D: u32> {
    /// Digest of `msg[..len]`.
    fn digest<let L: u32>(msg: [u8; L], len: u32) -> [u8; D];
}

/// SHA-1.
pub struct Sha1 {}
/// SHA-224.
pub struct Sha224 {}
/// SHA-256.
pub struct Sha256 {}
/// SHA-384.
pub struct Sha384 {}
/// SHA-512.
pub struct Sha512 {}

impl Digest<20> for Sha1 {
    fn digest<let L: u32>(msg: [u8; L], len: u32) -> [u8; 20] {
        sha1_var(msg, len)
    }
}

impl Digest<28> for Sha224 {
    fn digest<let L: u32>(msg: [u8; L], len: u32) -> [u8; 28] {
        sha224_var(msg, len)
    }
}

impl Digest<32> for Sha256 {
    fn digest<let L: u32>(msg: [u8; L], len: u32) -> [u8; 32] {
        sha256_var(msg, len)
    }
}

impl Digest<48> for Sha384 {
    fn digest<let L: u32>(msg: [u8; L], len: u32) -> [u8; 48] {
        sha384_var(msg, len)
    }
}

impl Digest<64> for Sha512 {
    fn digest<let L: u32>(msg: [u8; L], len: u32) -> [u8; 64] {
        sha512_var(msg, len)
    }
}
