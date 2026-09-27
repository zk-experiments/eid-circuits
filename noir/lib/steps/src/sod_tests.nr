//! Negative cases for the SOD step checks, each mutating one input of a
//! synthetic document. Positive cases are the generated tests in
//! sod_vectors.nr.

use crate::sod::{commitment, parse};
use crate::sod_vectors::{
    BP256_ATTRS, BP256_MD_OFFSET, BP256_TBS, P256_ATTRS, P256_MD_OFFSET, P256_TBS, PKCS1_2048_ATTRS,
    PKCS1_2048_MD_OFFSET, PKCS1_2048_TBS,
};
use eid_der::{curves, spki_ec, spki_rsa};

#[test(should_fail_with = "md_offset is not the start of an attribute")]
fn rejects_md_offset_inside_an_attribute() {
    let _ = parse(PKCS1_2048_TBS, PKCS1_2048_ATTRS, PKCS1_2048_MD_OFFSET + 2);
}

#[test(should_fail_with = "unexpected DER bytes")]
fn rejects_md_offset_at_another_attribute() {
    // The first attribute (contentType or signingTime) is not messageDigest.
    let _ = parse(PKCS1_2048_TBS, PKCS1_2048_ATTRS, 2);
}

#[test(should_fail_with = "bytes past the DER length must be zero")]
fn rejects_bytes_after_the_attributes() {
    let mut attrs = PKCS1_2048_ATTRS;
    attrs[255] = 1;
    let _ = parse(PKCS1_2048_TBS, attrs, PKCS1_2048_MD_OFFSET);
}

#[test(should_fail_with = "bytes past the DER length must be zero")]
fn rejects_bytes_after_the_certificate() {
    let mut tbs = PKCS1_2048_TBS;
    tbs[tbs.len() - 1] = 1;
    let _ = parse(tbs, PKCS1_2048_ATTRS, PKCS1_2048_MD_OFFSET);
}

#[test(should_fail_with = "unexpected DER tag")]
fn rejects_attributes_in_their_implicit_form() {
    // In the SOD the attributes are tagged [0] (0xA0); only the SET form is signed.
    let mut attrs = PKCS1_2048_ATTRS;
    attrs[0] = 0xa0;
    let _ = parse(PKCS1_2048_TBS, attrs, PKCS1_2048_MD_OFFSET);
}

#[test(should_fail_with = "unexpected DER bytes")]
fn rsa_key_is_not_an_ec_key() {
    let (f, _) = parse(PKCS1_2048_TBS, PKCS1_2048_ATTRS, PKCS1_2048_MD_OFFSET);
    let _ = spki_ec(PKCS1_2048_TBS, f.spki_offset, f.len, curves::P256);
}

#[test(should_fail_with = "unexpected DER bytes")]
fn ec_key_is_not_an_rsa_key() {
    let (f, _) = parse(P256_TBS, P256_ATTRS, P256_MD_OFFSET);
    let _ = spki_rsa::<_, 256>(P256_TBS, f.spki_offset, f.len);
}

#[test(should_fail_with = "unexpected DER bytes")]
fn named_curve_must_match() {
    let (f, _) = parse(P256_TBS, P256_ATTRS, P256_MD_OFFSET);
    let _ = spki_ec(P256_TBS, f.spki_offset, f.len, curves::BP256);
}

#[test(should_fail_with = "explicit curve prime does not match the circuit")]
fn explicit_curve_must_match() {
    let (f, _) = parse(BP256_TBS, BP256_ATTRS, BP256_MD_OFFSET);
    let _ = spki_ec(BP256_TBS, f.spki_offset, f.len, curves::P256);
}

#[test(should_fail_with = "INTEGER does not fit")]
fn rsa_modulus_must_fit_the_circuit() {
    let (f, _) = parse(PKCS1_2048_TBS, PKCS1_2048_ATTRS, PKCS1_2048_MD_OFFSET);
    let _ = spki_rsa::<_, 128>(PKCS1_2048_TBS, f.spki_offset, f.len);
}

#[test]
fn commitment_binds_every_input() {
    let (_, a) = parse(PKCS1_2048_TBS, PKCS1_2048_ATTRS, PKCS1_2048_MD_OFFSET);
    let c = commitment(1, [0x55, 0x54, 0x4f], a);
    assert(c != commitment(2, [0x55, 0x54, 0x4f], a));
    assert(c != commitment(1, [0x55, 0x54, 0x50], a));
    let mut b = a;
    b.digest[0] ^= 1;
    assert(c != commitment(1, [0x55, 0x54, 0x4f], b));
    b = a;
    b.digest_len = 20;
    assert(c != commitment(1, [0x55, 0x54, 0x4f], b));
}
