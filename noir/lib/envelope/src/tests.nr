//! Negative and structural cases. The generated vectors.nr checks agreement
//! with rust/eid-envelope.

use crate::{PLAINTEXT_FIELDS, seal, VIEWERS};
use std::embedded_curve_ops::EmbeddedCurvePoint;

fn no_viewers() -> [EmbeddedCurvePoint; VIEWERS] {
    [EmbeddedCurvePoint::point_at_infinity(); VIEWERS]
}

#[test(should_fail_with = "ephemeral scalar must not be zero")]
fn rejects_zero_ephemeral_scalar() {
    let _ = seal(no_viewers(), 0, 7, [0; PLAINTEXT_FIELDS]);
}

#[test]
fn empty_slots_wrap_nothing() {
    let env = seal(no_viewers(), 5, 7, [0; PLAINTEXT_FIELDS]);
    assert_eq(env.wrapped, [0; VIEWERS]);
}

#[test]
fn ciphertext_depends_on_key_and_ephemeral() {
    let p = [1; PLAINTEXT_FIELDS];
    let a = seal(no_viewers(), 5, 7, p);
    assert(a.ciphertext[0] != seal(no_viewers(), 5, 8, p).ciphertext[0]);
    assert(a.ciphertext[0] != seal(no_viewers(), 6, 7, p).ciphertext[0]);
}
