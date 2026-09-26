//! Cost benchmark: ECDSA on bp384, SHA-256 digest input.
//! Measured by `.github/scripts/circuit_sizes.py` (ACIR opcodes, bb gates).

use eid_ecdsa::verify_bp384;

fn main(x: [u8; 48], y: [u8; 48], r: [u8; 48], s: [u8; 48], digest: [u8; 32]) {
    verify_bp384::<32>(x, y, r, s, digest);
}
