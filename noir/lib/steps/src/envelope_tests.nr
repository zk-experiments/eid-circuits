//! Negative cases for the envelope step checks, each mutating one input of a
//! synthetic document. Positive cases are the generated tests in
//! envelope_vectors.nr.

use crate::envelope::{
    assert_hash_at, assert_message_digest, check, OID_SHA256, OID_SHA384, outputs, parse_dg1,
};
use crate::envelope_vectors::{DATE, EXPIRES, sha256_v0, SHA256_V0_DG1_HASH, sha512_v1_no_dg11};
use eid_hash::sha256_var;
use std::embedded_curve_ops::EmbeddedCurvePoint;

#[test]
fn valid_on_its_last_day() {
    let _ = check::<512, 11, 32>(EXPIRES, sha256_v0(), OID_SHA256);
}

#[test(should_fail_with = "document has expired at the given date")]
fn rejects_expired_document() {
    let _ = check::<512, 11, 32>(EXPIRES + 1, sha256_v0(), OID_SHA256);
}

#[test(should_fail_with = "issuing state does not match the registry country")]
fn rejects_other_country() {
    let mut w = sha256_v0();
    w.country = [0x44, 0x45, 0x55];
    let _ = check::<512, 11, 32>(DATE, w, OID_SHA256);
}

#[test(should_fail_with = "unexpected DER bytes")]
fn rejects_other_hash_algorithm() {
    let _ = check::<512, 11, 32>(DATE, sha256_v0(), OID_SHA384);
}

#[test(should_fail_with = "dg1_offset is not DG1's entry")]
fn rejects_dg1_offset_at_another_entry() {
    let mut w = sha256_v0();
    w.dg1_offset = w.dg1_offset + 39;
    let _ = check::<512, 11, 32>(DATE, w, OID_SHA256);
}

#[test(should_fail_with = "DG11 is listed but has_dg11 is false")]
fn rejects_hiding_a_listed_dg11() {
    let mut w = sha256_v0();
    w.has_dg11 = false;
    w.dg11 = [0; 512];
    let _ = check::<512, 11, 32>(DATE, w, OID_SHA256);
}

#[test(should_fail_with = "DG11 must be listed exactly once")]
fn rejects_dg11_the_document_does_not_list() {
    let mut w = sha512_v1_no_dg11();
    w.has_dg11 = true;
    w.dg11[0] = 0x6b;
    let _ = check::<512, 11, 64>(DATE, w, crate::envelope::OID_SHA512);
}

#[test(should_fail_with = "bytes past the DER length must be zero")]
fn rejects_bytes_after_the_econtent() {
    let mut w = sha256_v0();
    w.econtent[511] = 1;
    let _ = check::<512, 11, 32>(DATE, w, OID_SHA256);
}

#[test(should_fail_with = "bytes past the DER length must be zero")]
fn rejects_dg11_bytes_when_absent() {
    let mut w = sha512_v1_no_dg11();
    w.dg11[3] = 1;
    let _ = check::<512, 11, 64>(DATE, w, crate::envelope::OID_SHA512);
}

#[test(should_fail_with = "messageDigest does not match the eContent")]
fn rejects_other_message_digest() {
    let mut w = sha256_v0();
    w.digest[5] ^= 1;
    let p = check::<512, 11, 32>(DATE, w, OID_SHA256);
    assert_message_digest(w, sha256_var(w.econtent, p.lds.len));
}

#[test(should_fail_with = "data group hash does not match the LDS security object")]
fn rejects_tampered_dg1() {
    // Change the first name letter; the MRZ still parses and the date holds.
    let mut w = sha256_v0();
    w.dg1[20] = 0x42;
    let p = check::<512, 11, 32>(DATE, w, OID_SHA256);
    assert_hash_at(w.econtent, p.lds.dg1_hash_at, sha256_var(w.dg1, p.dg1.len));
}

#[test]
fn dg1_hash_is_listed() {
    let w = sha256_v0();
    let p = check::<512, 11, 32>(DATE, w, OID_SHA256);
    assert_eq(sha256_var(w.dg1, p.dg1.len), SHA256_V0_DG1_HASH);
    assert_hash_at(w.econtent, p.lds.dg1_hash_at, SHA256_V0_DG1_HASH);
}

#[test(should_fail_with = "MRZ must be TD1, TD2 or TD3")]
fn rejects_other_mrz_length() {
    let mut dg1 = sha256_v0().dg1;
    // 87-character MRZ: shorten both lengths and drop the last byte.
    dg1[1] = 0x5a;
    dg1[4] = 87;
    dg1[92] = 0;
    let _ = parse_dg1(dg1);
}

#[test]
fn outputs_bind_step_b_and_the_data_groups() {
    let w = sha256_v0();
    let p = check::<512, 11, 32>(DATE, w, OID_SHA256);
    let viewers = [EmbeddedCurvePoint::point_at_infinity(); 4];
    let a = outputs(viewers, w, p, 3, 3);
    let mut v = w;
    v.sod_salt = 1;
    assert(a.sod_commitment != outputs(viewers, v, p, 3, 3).sod_commitment);
    v = w;
    v.dg1[20] = 0x42;
    assert(a.envelope.ciphertext != outputs(viewers, v, p, 3, 3).envelope.ciphertext);
}
