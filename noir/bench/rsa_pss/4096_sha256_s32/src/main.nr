//! Cost benchmark: RSASSA-PSS, RSA-4096, SHA256 with MGF1-SHA256, 32-byte salt, 17-bit exponent.
//! Measured by `.github/scripts/circuit_sizes.py` (ACIR opcodes, bb gates).

use eid_hash::Sha256;
use eid_rsa::verify_pss;

fn main(
    modulus: [u8; 512],
    redc: [u128; 35],
    exponent: u32,
    signature: [u8; 512],
    digest: [u8; 32],
) {
    verify_pss::<Sha256, 35, 4096, 17, 32, 32>(modulus, redc, exponent, signature, digest);
}
