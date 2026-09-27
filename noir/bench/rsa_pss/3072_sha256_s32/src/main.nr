//! Cost benchmark: RSASSA-PSS, RSA-3072, SHA256 with MGF1-SHA256, 32-byte salt, 17-bit exponent.
//! Measured by `.github/scripts/circuit_sizes.py` (ACIR opcodes, bb gates).

use eid_hash::Sha256;
use eid_rsa::verify_pss;

fn main(
    modulus: [u8; 384],
    redc: [u128; 26],
    exponent: u32,
    signature: [u8; 384],
    digest: [u8; 32],
) {
    verify_pss::<Sha256, 26, 3072, 17, 32, 32>(modulus, redc, exponent, signature, digest);
}
