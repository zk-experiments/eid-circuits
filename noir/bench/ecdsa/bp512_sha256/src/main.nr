//! Cost benchmark: ECDSA on bp512, SHA-256 digest input.
//! Measured by `.github/scripts/circuit_sizes.py` (ACIR opcodes, bb gates).

use eid_ecdsa::verify_bp512;

fn main(x: [u8; 64], y: [u8; 64], r: [u8; 64], s: [u8; 64], digest: [u8; 32]) {
    verify_bp512::<32>(x, y, r, s, digest);
}
