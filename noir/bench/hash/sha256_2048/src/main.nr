//! Cost benchmark: SHA256 over up to 2048 bytes (variable length).
//! Measured by `.github/scripts/circuit_sizes.py` (ACIR opcodes, bb gates).

use eid_hash::sha256_var;

fn main(msg: [u8; 2048], len: u32) -> pub [u8; 32] {
    sha256_var(msg, len)
}
