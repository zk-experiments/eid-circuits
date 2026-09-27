//! Cost benchmark: RSASSA-PKCS1-v1_5, RSA-6144, SHA-256 digest input, 17-bit exponent.
//! Measured by `.github/scripts/circuit_sizes.py` (ACIR opcodes, bb gates).

use eid_rsa::{DIGEST_INFO_SHA256, verify_pkcs1v15};

fn main(
    modulus: [u8; 768],
    redc: [u128; 52],
    exponent: u32,
    signature: [u8; 768],
    digest: [u8; 32],
) {
    verify_pkcs1v15::<52, 6144, 17, 32, 19>(
        modulus,
        redc,
        exponent,
        signature,
        digest,
        DIGEST_INFO_SHA256,
    );
}
