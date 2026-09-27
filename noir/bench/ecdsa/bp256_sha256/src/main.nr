//! Cost benchmark: ECDSA on bp256, SHA-256 digest input.
//! Measured by `.github/scripts/circuit_sizes.py` (ACIR opcodes, bb gates).

use eid_ecdsa::verify_bp256;

fn main(x: [u8; 32], y: [u8; 32], r: [u8; 32], s: [u8; 32], digest: [u8; 32]) {
    verify_bp256::<32>(x, y, r, s, digest);
}
