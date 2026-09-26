//! Cost benchmark: RSASSA-PSS, RSA-4096, SHA512 with MGF1-SHA512, 64-byte salt, 17-bit exponent.
//! Measured by `.github/scripts/circuit_sizes.py` (ACIR opcodes, bb gates).

use eid_hash::Sha512;
use eid_rsa::verify_pss;

fn main(
    modulus: [u8; 512],
    redc: [u128; 35],
    exponent: u32,
    signature: [u8; 512],
    digest: [u8; 64],
) {
    verify_pss::<Sha512, 35, 4096, 17, 64, 64>(modulus, redc, exponent, signature, digest);
}
