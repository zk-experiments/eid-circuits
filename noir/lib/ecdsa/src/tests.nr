//! Curve-parameter checks for the generated curves, and negative cases.
//! Positive cases are the generated tests in vectors.nr (real certificate
//! signatures on all six curves).

use crate::{digest_to_scalar_bytes, verify_bp256, verify_p256, verify_p521};
use crate::vectors::{
    ECDSA_SHA1_BP256_LT_R, ECDSA_SHA1_BP256_LT_S, ECDSA_SHA1_BP256_LT_TBS, ECDSA_SHA1_BP256_LT_X,
    ECDSA_SHA1_BP256_LT_Y, ECDSA_SHA256_P256_BE_R, ECDSA_SHA256_P256_BE_S, ECDSA_SHA256_P256_BE_TBS,
    ECDSA_SHA256_P256_BE_X, ECDSA_SHA256_P256_BE_Y, ECDSA_SHA256_P521_LT_R, ECDSA_SHA256_P521_LT_S,
    ECDSA_SHA256_P521_LT_X, ECDSA_SHA256_P521_LT_Y,
};
use bignum::BigNum;
use eid_hash::{sha1_var, sha256_var};
use noir_bigcurve::BigCurve;
use noir_bigcurve::curves::eid_bp256::{BP256_Fq, BP256_Fr, BP256_Fr_PARAMS, BrainpoolP256r1};
use noir_bigcurve::curves::eid_bp384::{BP384_Fq, BrainpoolP384r1};
use noir_bigcurve::curves::eid_bp512::{BP512_Fq, BrainpoolP512r1};
use noir_bigcurve::curves::eid_p521::{P521, P521_Fq};
use std::ops::Neg;

/// The generator and both offset generators are on the curve.
///
/// Group order and `final = 2^(4·(S − 1))·offset` are checked by the Rust
/// generator's unit tests with independent big-integer arithmetic: here they
/// would need point additions of a point with itself (or its negation), which
/// noir_bigcurve's incomplete formulas reject by design. Every generated
/// constant is also exercised end to end by the real-signature vectors.
fn check_curve<C, Fq>()
where
    C: BigCurve<Fq>,
    Fq: BigNum,
{
    C::one().validate_on_curve();
    C::offset_generator().validate_on_curve();
    C::offset_generator_final().validate_on_curve();
    assert(C::offset_generator() != C::one(), "offset generator equals G");
}

#[test]
fn generated_curve_points_are_on_their_curves() {
    check_curve::<BrainpoolP256r1, BP256_Fq>();
    check_curve::<BrainpoolP384r1, BP384_Fq>();
    check_curve::<BrainpoolP512r1, BP512_Fq>();
    check_curve::<P521, P521_Fq>();
}

fn bp256_digest() -> [u8; 20] {
    sha1_var(ECDSA_SHA1_BP256_LT_TBS, ECDSA_SHA1_BP256_LT_TBS.len())
}

fn p256_digest() -> [u8; 32] {
    sha256_var(ECDSA_SHA256_P256_BE_TBS, ECDSA_SHA256_P256_BE_TBS.len())
}

#[test(should_fail_with = "ECDSA signature mismatch")]
fn rejects_tampered_r() {
    let mut r = ECDSA_SHA1_BP256_LT_R;
    r[31] ^= 1;
    verify_bp256(
        ECDSA_SHA1_BP256_LT_X,
        ECDSA_SHA1_BP256_LT_Y,
        r,
        ECDSA_SHA1_BP256_LT_S,
        bp256_digest(),
    );
}

#[test(should_fail_with = "ECDSA signature mismatch")]
fn rejects_tampered_s() {
    let mut s = ECDSA_SHA1_BP256_LT_S;
    s[0] ^= 1;
    verify_bp256(
        ECDSA_SHA1_BP256_LT_X,
        ECDSA_SHA1_BP256_LT_Y,
        ECDSA_SHA1_BP256_LT_R,
        s,
        bp256_digest(),
    );
}

#[test(should_fail_with = "ECDSA signature mismatch")]
fn rejects_other_message() {
    let mut digest = p256_digest();
    digest[5] ^= 1;
    verify_p256(
        ECDSA_SHA256_P256_BE_X,
        ECDSA_SHA256_P256_BE_Y,
        ECDSA_SHA256_P256_BE_R,
        ECDSA_SHA256_P256_BE_S,
        digest,
    );
}

#[test(should_fail_with = "ECDSA signature mismatch")]
fn rejects_other_key() {
    // Another valid brainpoolP256r1 point: -Q.
    let q = BrainpoolP256r1::from_coordinates(
        BP256_Fq::from_be_bytes(ECDSA_SHA1_BP256_LT_X),
        BP256_Fq::from_be_bytes(ECDSA_SHA1_BP256_LT_Y),
        false,
    );
    let neg = q.neg();
    verify_bp256(
        neg.x().to_be_bytes(),
        neg.y().to_be_bytes(),
        ECDSA_SHA1_BP256_LT_R,
        ECDSA_SHA1_BP256_LT_S,
        bp256_digest(),
    );
}

#[test(should_fail)]
fn rejects_key_off_curve() {
    let mut y = ECDSA_SHA1_BP256_LT_Y;
    y[31] ^= 1;
    verify_bp256(
        ECDSA_SHA1_BP256_LT_X,
        y,
        ECDSA_SHA1_BP256_LT_R,
        ECDSA_SHA1_BP256_LT_S,
        bp256_digest(),
    );
}

#[test(should_fail)]
fn rejects_zero_r() {
    verify_bp256(
        ECDSA_SHA1_BP256_LT_X,
        ECDSA_SHA1_BP256_LT_Y,
        [0; 32],
        ECDSA_SHA1_BP256_LT_S,
        bp256_digest(),
    );
}

#[test(should_fail)]
fn rejects_s_equal_to_n() {
    let n: [u8; 32] = BP256_Fr::from_limbs(BP256_Fr_PARAMS.modulus).to_be_bytes();
    verify_bp256(
        ECDSA_SHA1_BP256_LT_X,
        ECDSA_SHA1_BP256_LT_Y,
        ECDSA_SHA1_BP256_LT_R,
        n,
        bp256_digest(),
    );
}

#[test(should_fail_with = "P-521 digests are at most 65 bytes")]
fn p521_rejects_oversized_digest() {
    verify_p521::<66>(
        ECDSA_SHA256_P521_LT_X,
        ECDSA_SHA256_P521_LT_Y,
        ECDSA_SHA256_P521_LT_R,
        ECDSA_SHA256_P521_LT_S,
        [0; 66],
    );
}

#[test]
fn digest_truncation_and_padding() {
    let d: [u8; 4] = [1, 2, 3, 4];
    assert_eq(digest_to_scalar_bytes::<4, 2>(d), [1, 2]);
    assert_eq(digest_to_scalar_bytes::<4, 6>(d), [0, 0, 1, 2, 3, 4]);
}
