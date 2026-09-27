//! Cost benchmark: RSASSA-PKCS1-v1_5, RSA-4096, SHA-256 digest input, 17-bit exponent.
//! Measured by `.github/scripts/circuit_sizes.py` (ACIR opcodes, bb gates).

use eid_rsa::{DIGEST_INFO_SHA256, verify_pkcs1v15};

fn main(
    modulus: [u8; 512],
    redc: [u128; 35],
    exponent: u32,
    signature: [u8; 512],
    digest: [u8; 32],
) {
    verify_pkcs1v15::<35, 4096, 17, 32, 19>(
        modulus,
        redc,
        exponent,
        signature,
        digest,
        DIGEST_INFO_SHA256,
    );
}
