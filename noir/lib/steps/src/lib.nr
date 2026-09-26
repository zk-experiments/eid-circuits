//! Checks shared by the step circuits in `noir/circuits`. Each step circuit is
//! a thin binary that hashes and verifies one signature with the library for
//! its signature group, and calls into this library for everything else.
//! Specification and review notes: README.md.

pub mod dsc;
mod tests;
mod vectors;

/// Hash identifiers exposed by every step (same numbering as `eid_hash`).
pub global HASH_SHA1: u8 = 1;
pub global HASH_SHA224: u8 = 2;
pub global HASH_SHA256: u8 = 3;
pub global HASH_SHA384: u8 = 4;
pub global HASH_SHA512: u8 = 5;
