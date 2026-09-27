//! Envelope encryption of DG1 and DG11 to viewer keys: a Grumpkin KEM and a
//! Poseidon2 duplex. `rust/eid-envelope` implements the same construction
//! for provers (`seal`) and viewers (`open`), and the generated vectors check
//! both agree. Specification and review notes: README.md.

mod tests;
mod vectors;

use csca_registry::{hash, pack_be};
use std::embedded_curve_ops::{
    EmbeddedCurvePoint, EmbeddedCurveScalar, fixed_base_scalar_mul, multi_scalar_mul,
};

/// Viewer slots per envelope.
pub global VIEWERS: u32 = 4;
/// DG1 buffer size (a TD1 MRZ with its tags is 95 bytes).
pub global DG1_MAX: u32 = 95;
/// DG11 buffer size.
pub global DG11_MAX: u32 = 512;
/// Header, 4 DG1 fields and 17 DG11 fields, padded to whole blocks of 3.
pub global PLAINTEXT_FIELDS: u32 = 24;
/// "eid-envelope/wrap/v1" as a big-endian integer.
pub global WRAP_DOMAIN: Field = 0x6569642d656e76656c6f70652f777261702f7631;
/// "eid-envelope/cipher/v1" as a big-endian integer.
pub global CIPHER_DOMAIN: Field = 0x6569642d656e76656c6f70652f6369706865722f7631;

/// What a proof publishes.
pub struct Envelope {
    /// `E = e·G`.
    pub ephemeral: EmbeddedCurvePoint,
    /// `K + kᵢ` per viewer slot; 0 for an empty slot (the point at infinity, `(0, 0)`).
    pub wrapped: [Field; VIEWERS],
    pub ciphertext: [Field; PLAINTEXT_FIELDS],
}

/// The plaintext: `dg1_len + 2^16·dg11_len`, then `pack_be(dg1)` and
/// `pack_be(dg11)` over the whole zero-padded buffers, then zeros. The
/// caller asserts the buffers are zero past their lengths.
pub fn plaintext(
    dg1: [u8; DG1_MAX],
    dg1_len: u32,
    dg11: [u8; DG11_MAX],
    dg11_len: u32,
) -> [Field; PLAINTEXT_FIELDS] {
    let a: [Field; 4] = pack_be(dg1);
    let b: [Field; 17] = pack_be(dg11);
    let mut out: [Field; PLAINTEXT_FIELDS] = [0; PLAINTEXT_FIELDS];
    out[0] = dg1_len as Field + (dg11_len as Field) * 65536;
    for i in 0..4 {
        out[1 + i] = a[i];
    }
    for i in 0..17 {
        out[5 + i] = b[i];
    }
    out
}

/// Seals `plaintext` under data key `key` with ephemeral scalar `e`, wrapping
/// `key` to every viewer key that is not the point at infinity.
///
/// `e` and `key` must be fresh and uniformly random per envelope; `e ≠ 0` is
/// asserted. Viewer keys are public inputs: the verifier is responsible for
/// them being real Grumpkin keys.
pub fn seal(
    viewers: [EmbeddedCurvePoint; VIEWERS],
    e: Field,
    key: Field,
    plaintext: [Field; PLAINTEXT_FIELDS],
) -> Envelope {
    assert(e != 0, "ephemeral scalar must not be zero");
    let s = EmbeddedCurveScalar::from_field(e);
    let ephemeral = fixed_base_scalar_mul(s);

    let mut wrapped: [Field; VIEWERS] = [0; VIEWERS];
    for i in 0..VIEWERS {
        let shared = multi_scalar_mul([viewers[i]], [s]);
        let k = hash([WRAP_DOMAIN, shared.x, shared.y, i as Field]);
        wrapped[i] = if viewers[i].is_infinite() { 0 } else { key + k };
    }

    let mut state: [Field; 4] =
        std::hash::poseidon2_permutation([key, ephemeral.x, ephemeral.y, CIPHER_DOMAIN]);
    let mut ciphertext: [Field; PLAINTEXT_FIELDS] = [0; PLAINTEXT_FIELDS];
    for block in 0..PLAINTEXT_FIELDS / 3 {
        for j in 0..3 {
            let c = plaintext[3 * block + j] + state[j];
            ciphertext[3 * block + j] = c;
            state[j] = c;
        }
        state = std::hash::poseidon2_permutation(state);
    }
    Envelope { ephemeral, wrapped, ciphertext }
}
