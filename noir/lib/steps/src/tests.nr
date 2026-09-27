//! Negative cases for `dsc::check`, each mutating one input of a real case
//! (the IS RSA-2048 root standing in for a DSC). Positive cases are the
//! generated tests in vectors.nr.

use crate::dsc::{check, commitment, KeyKind};
use crate::vectors::{
    pkcs1_sha256_2048_is_kind, PKCS1_SHA256_2048_IS_NOT_BEFORE_OFFSET,
    PKCS1_SHA256_2048_IS_SERIAL_OFFSET, pkcs1_sha256_2048_is_witness, ROOT,
};

#[test(should_fail_with = "CSCA key size does not match the circuit")]
fn rejects_leaf_of_another_key_size() {
    let kind = KeyKind { key_type: 1, curve: 0, bits: 4096 };
    let _ = check::<1000, 256, 9>(ROOT, pkcs1_sha256_2048_is_witness(), kind);
}

#[test(should_fail_with = "CSCA key type does not match the circuit")]
fn rejects_leaf_of_another_key_type() {
    let kind = KeyKind { key_type: 2, curve: 0, bits: 2048 };
    let _ = check::<1000, 256, 9>(ROOT, pkcs1_sha256_2048_is_witness(), kind);
}

#[test(should_fail_with = "bytes past the DER length must be zero")]
fn rejects_bytes_after_the_certificate() {
    let mut w = pkcs1_sha256_2048_is_witness();
    w.tbs[999] = 1;
    let _ = check::<1000, 256, 9>(ROOT, w, pkcs1_sha256_2048_is_kind());
}

#[test(should_fail_with = "registry root mismatch")]
fn rejects_other_root() {
    let _ = check::<1000, 256, 9>(
        ROOT + 1,
        pkcs1_sha256_2048_is_witness(),
        pkcs1_sha256_2048_is_kind(),
    );
}

#[test(should_fail_with = "CSCA key period has not opened at the given date")]
fn rejects_dsc_issued_before_the_csca_period() {
    // Turn the notBefore year (UTCTime YY) into 1999, before the CSCA existed.
    let mut w = pkcs1_sha256_2048_is_witness();
    let at = PKCS1_SHA256_2048_IS_NOT_BEFORE_OFFSET + 2;
    w.tbs[at] = 0x39;
    w.tbs[at + 1] = 0x39;
    let _ = check::<1000, 256, 9>(ROOT, w, pkcs1_sha256_2048_is_kind());
}

#[test(should_fail)]
fn exclusion_is_bound_to_the_serial() {
    // Same witness, different serial: the non-revocation proof no longer fits.
    let mut w = pkcs1_sha256_2048_is_witness();
    let last = PKCS1_SHA256_2048_IS_SERIAL_OFFSET
        + 2
        + (w.tbs[PKCS1_SHA256_2048_IS_SERIAL_OFFSET + 1] as u32)
        - 1;
    w.tbs[last] ^= 0x01;
    let _ = check::<1000, 256, 9>(ROOT, w, pkcs1_sha256_2048_is_kind());
}

#[test(should_fail_with = "unexpected DER tag")]
fn rejects_non_sequence_input() {
    let mut w = pkcs1_sha256_2048_is_witness();
    w.tbs[0] = 0x31;
    let _ = check::<1000, 256, 9>(ROOT, w, pkcs1_sha256_2048_is_kind());
}

#[test]
fn commitment_binds_every_input() {
    let w = pkcs1_sha256_2048_is_witness();
    let base = commitment(7, [0x49, 0x53, 0x4c], 3, w.tbs, 900);
    let mut other = w.tbs;
    other[5] ^= 1;
    assert(commitment(8, [0x49, 0x53, 0x4c], 3, w.tbs, 900) != base, "salt");
    assert(commitment(7, [0x49, 0x53, 0x4d], 3, w.tbs, 900) != base, "country");
    assert(commitment(7, [0x49, 0x53, 0x4c], 1, w.tbs, 900) != base, "hash id");
    assert(commitment(7, [0x49, 0x53, 0x4c], 3, w.tbs, 901) != base, "length");
    assert(commitment(7, [0x49, 0x53, 0x4c], 3, other, 900) != base, "tbs");
}
