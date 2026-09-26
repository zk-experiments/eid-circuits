//! Cost benchmark: SHA1 over up to 2048 bytes (variable length).
//! Measured by `.github/scripts/circuit_sizes.py` (ACIR opcodes, bb gates).

use eid_hash::sha1_var;

fn main(msg: [u8; 2048], len: u32) -> pub [u8; 20] {
    sha1_var(msg, len)
}
