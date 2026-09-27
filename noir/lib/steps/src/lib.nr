//! Checks shared by the step circuits in `noir/circuits`. Each step circuit is
//! a thin binary that hashes and verifies one signature with the library for
//! its signature group, and calls into this library for everything else.
//! Specification and review notes: README.md.

pub mod dsc;
pub mod envelope;
pub mod sod;
mod envelope_tests;
mod envelope_vectors;
mod sod_tests;
mod sod_vectors;
mod tests;
mod vectors;

/// Hash identifiers exposed by every step (same numbering as `eid_hash`).
pub global HASH_SHA1: u8 = 1;
pub global HASH_SHA224: u8 = 2;
pub global HASH_SHA256: u8 = 3;
pub global HASH_SHA384: u8 = 4;
pub global HASH_SHA512: u8 = 5;

/// A country's three ICAO letters as one field element (big-endian).
pub fn country_field(country: [u8; 3]) -> Field {
    (country[0] as Field) * 65536 + (country[1] as Field) * 256 + (country[2] as Field)
}
