//! RSA signature verification (RFC 8017) for eMRTD PKIs: RSASSA-PKCS1-v1_5
//! and RSASSA-PSS with MGF1, over `noir-lang/noir-bignum`.
//!
//! Sizes are compile-time: `MOD_BITS` is the modulus size in bits (a multiple
//! of 8; the modulus must have its top bit set), `N = ceil(MOD_BITS / 120)`
//! limbs, `E_BITS` bounds the public exponent (`exponent < 2^E_BITS`).
//! Specification and review notes: README.md.

mod tests;
mod vectors;

use bignum::params::BigNumParams;
use bignum::RuntimeBigNum;
use eid_hash::Digest;

/// DigestInfo prefixes (RFC 8017 §9.2 note 1) for EMSA-PKCS1-v1_5.
pub global DIGEST_INFO_SHA1: [u8; 15] =
    [0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14];
pub global DIGEST_INFO_SHA224: [u8; 19] = [
    0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
    0x00, 0x04, 0x1c,
];
pub global DIGEST_INFO_SHA256: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
pub global DIGEST_INFO_SHA384: [u8; 19] = [
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30,
];
pub global DIGEST_INFO_SHA512: [u8; 19] = [
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];

/// Modulus limbs (120-bit, little-endian) from big-endian bytes, with the top
/// bit asserted set so the modulus is exactly `MOD_BITS` bits.
fn modulus_limbs<let N: u32, let MOD_BITS: u32>(modulus: [u8; (MOD_BITS + 7) / 8]) -> [u128; N] {
    assert_eq(MOD_BITS % 8, 0, "MOD_BITS must be a multiple of 8");
    assert(modulus[0] >= 0x80, "modulus must have its top bit set");
    let mut limbs: [u128; N] = [0; N];
    for i in 0..(MOD_BITS / 8) {
        let from_end = MOD_BITS / 8 - 1 - i;
        let limb = from_end / 15;
        limbs[limb] += (modulus[i] as u128) << ((from_end % 15) as u128 * 8);
    }
    limbs
}

/// `signature^exponent mod modulus`, with `signature < modulus` asserted.
///
/// `redc` is the Barrett parameter `floor(2^(2·MOD_BITS + 6) / modulus)` in
/// 120-bit limbs. noir-bignum only uses it in unconstrained witness
/// generation, so a wrong value makes proving fail but cannot make a false
/// statement verify.
pub fn rsa<let N: u32, let MOD_BITS: u32, let E_BITS: u32>(
    modulus: [u8; (MOD_BITS + 7) / 8],
    redc: [u128; N],
    exponent: u32,
    signature: [u8; (MOD_BITS + 7) / 8],
) -> RuntimeBigNum<N, MOD_BITS> {
    assert(E_BITS <= 32, "E_BITS must be at most 32");
    assert((exponent as u64) < (1 << (E_BITS as u64)), "exponent does not fit E_BITS");
    assert(exponent % 2 == 1, "RSA exponent must be odd");
    let params = BigNumParams::new(false, modulus_limbs::<N, MOD_BITS>(modulus), redc);
    let s: RuntimeBigNum<N, MOD_BITS> = RuntimeBigNum::from_be_bytes(params, signature);
    // RFC 8017 §5.2.2 step 1: the signature representative must be below n.
    s.validate_in_field();
    // Left-to-right square-and-multiply over E_BITS bits.
    let mut acc: RuntimeBigNum<N, MOD_BITS> = RuntimeBigNum::one(params);
    for i in 0..E_BITS {
        acc = acc.sqr();
        let multiplied = acc * s;
        if ((exponent >> (E_BITS - 1 - i)) & 1) == 1 {
            acc = multiplied;
        }
    }
    acc
}

/// Asserts `signature` is a valid RSASSA-PKCS1-v1_5 signature on a message
/// whose `D`-byte digest is `digest`, with `digest_info` the `P`-byte
/// DigestInfo prefix for that hash (`DIGEST_INFO_*`).
///
/// Encoding: `EM = 0x00 ‖ 0x01 ‖ 0xFF… ‖ 0x00 ‖ DigestInfo ‖ digest` (RFC
/// 8017 §9.2), checked as `signature^e ≡ EM (mod n)`.
pub fn verify_pkcs1v15<let N: u32, let MOD_BITS: u32, let E_BITS: u32, let D: u32, let P: u32>(
    modulus: [u8; (MOD_BITS + 7) / 8],
    redc: [u128; N],
    exponent: u32,
    signature: [u8; (MOD_BITS + 7) / 8],
    digest: [u8; D],
    digest_info: [u8; P],
) {
    let k = MOD_BITS / 8;
    assert(k >= P + D + 11, "modulus too short for EMSA-PKCS1-v1_5");
    let mut em: [u8; (MOD_BITS + 7) / 8] = [0xff; (MOD_BITS + 7) / 8];
    em[0] = 0x00;
    em[1] = 0x01;
    em[k - P - D - 1] = 0x00;
    for i in 0..P {
        em[k - P - D + i] = digest_info[i];
    }
    for i in 0..D {
        em[k - D + i] = digest[i];
    }
    let m = rsa::<N, MOD_BITS, E_BITS>(modulus, redc, exponent, signature);
    let params = BigNumParams::new(false, modulus_limbs::<N, MOD_BITS>(modulus), redc);
    let expected: RuntimeBigNum<N, MOD_BITS> = RuntimeBigNum::from_be_bytes(params, em);
    assert(m == expected, "RSA PKCS#1 v1.5 signature mismatch");
}

/// MGF1 (RFC 8017 §B.2.1) over hash `H`: the first `L` bytes of
/// `H(seed ‖ 0x00000000) ‖ H(seed ‖ 0x00000001) ‖ …`.
pub fn mgf1<H, let D: u32, let L: u32>(seed: [u8; D]) -> [u8; L]
where
    H: Digest<D>,
{
    let mut out: [u8; L] = [0; L];
    for c in 0..((L + D - 1) / D) {
        let mut input: [u8; D + 4] = [0; D + 4];
        for i in 0..D {
            input[i] = seed[i];
        }
        input[D + 3] = c as u8;
        input[D + 2] = (c >> 8) as u8;
        let block = H::digest(input, D + 4);
        for i in 0..D {
            if c * D + i < L {
                out[c * D + i] = block[i];
            }
        }
    }
    out
}

/// Asserts `signature` is a valid RSASSA-PSS signature (RFC 8017 §8.1.2,
/// §9.1.2) on a message whose digest under `H` is `digest`, with MGF1 over
/// the same `H` and an `S`-byte salt.
///
/// With `emBits = MOD_BITS - 1` and the top modulus bit set, `emLen = k`
/// bytes and exactly one leading bit of `EM` must be zero.
pub fn verify_pss<H, let N: u32, let MOD_BITS: u32, let E_BITS: u32, let D: u32, let S: u32>(
    modulus: [u8; (MOD_BITS + 7) / 8],
    redc: [u128; N],
    exponent: u32,
    signature: [u8; (MOD_BITS + 7) / 8],
    digest: [u8; D],
)
where
    H: Digest<D>,
{
    let k = MOD_BITS / 8;
    assert(k >= D + S + 2, "modulus too short for EMSA-PSS");
    let m = rsa::<N, MOD_BITS, E_BITS>(modulus, redc, exponent, signature);
    // Canonical representative (< n) before reading bytes: noir-bignum results
    // are only reduced modulo n up to representation.
    m.validate_in_field();
    let em: [u8; (MOD_BITS + 7) / 8] = m.to_be_bytes();

    assert_eq(em[k - 1], 0xbc, "PSS trailer is not 0xbc");
    assert_eq(em[0] & 0x80, 0, "PSS leftmost bit of EM must be zero");
    let mut h: [u8; D] = [0; D];
    for i in 0..D {
        h[i] = em[k - D - 1 + i];
    }
    // dbMask for the whole k-byte buffer; only the first k - D - 1 bytes are used.
    let mask: [u8; (MOD_BITS + 7) / 8] = mgf1::<H, D, (MOD_BITS + 7) / 8>(h);
    let ps_len = k - D - S - 2;
    let mut m_prime: [u8; 8 + D + S] = [0; 8 + D + S];
    for i in 0..D {
        m_prime[8 + i] = digest[i];
    }
    for i in 0..(MOD_BITS / 8) {
        if i < k - D - 1 {
            let mut db = em[i] ^ mask[i];
            if i == 0 {
                db &= 0x7f;
            }
            if i < ps_len {
                assert_eq(db, 0, "PSS padding string must be zero");
            } else if i == ps_len {
                assert_eq(db, 0x01, "PSS separator must be 0x01");
            } else {
                m_prime[8 + D + (i - ps_len - 1)] = db;
            }
        }
    }
    assert_eq(H::digest(m_prime, 8 + D + S), h, "RSA-PSS signature mismatch");
}
