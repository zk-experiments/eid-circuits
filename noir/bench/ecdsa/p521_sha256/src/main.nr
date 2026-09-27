//! Cost benchmark: ECDSA on p521, SHA-256 digest input.
//! Measured by `.github/scripts/circuit_sizes.py` (ACIR opcodes, bb gates).

use eid_ecdsa::verify_p521;

fn main(x: [u8; 66], y: [u8; 66], r: [u8; 66], s: [u8; 66], digest: [u8; 32]) {
    verify_p521::<32>(x, y, r, s, digest);
}
