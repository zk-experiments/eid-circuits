//! Negative and structural cases. The generated vectors.nr checks agreement
//! with rust/eid-envelope.

use crate::{nullifier, PLAINTEXT_FIELDS, seal, VIEWERS};
use std::embedded_curve_ops::EmbeddedCurvePoint;

fn no_viewers() -> [EmbeddedCurvePoint; VIEWERS] {
    [EmbeddedCurvePoint::point_at_infinity(); VIEWERS]
}

#[test(should_fail_with = "ephemeral scalar must not be zero")]
fn rejects_zero_ephemeral_scalar() {
    let _ = seal(no_viewers(), 0, 7, 0, [0; PLAINTEXT_FIELDS]);
}

#[test]
fn empty_slots_wrap_nothing() {
    let env = seal(no_viewers(), 5, 7, 0, [0; PLAINTEXT_FIELDS]);
    assert_eq(env.wrapped, [0; VIEWERS]);
}

#[test]
fn ciphertext_depends_on_key_ephemeral_and_context() {
    let p = [1; PLAINTEXT_FIELDS];
    let a = seal(no_viewers(), 5, 7, 9, p);
    assert(a.ciphertext[0] != seal(no_viewers(), 5, 8, 9, p).ciphertext[0]);
    assert(a.ciphertext[0] != seal(no_viewers(), 6, 7, 9, p).ciphertext[0]);
    assert(a.ciphertext[0] != seal(no_viewers(), 5, 7, 10, p).ciphertext[0]);
}

#[test]
fn nullifier_is_zero_without_scope_and_scoped_otherwise() {
    let mut d = [0; 64];
    d[0] = 1;
    assert_eq(nullifier(0, d, 32), 0);
    assert_eq(nullifier(5, d, 32), nullifier(5, d, 32));
    assert(nullifier(5, d, 32) != nullifier(6, d, 32));
    assert(nullifier(5, d, 32) != nullifier(5, d, 48));
}
