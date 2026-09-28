//! Envelope encryption of DG1 to viewer keys: a Grumpkin KEM and a
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
pub global VIEWERS: u32 = 1;
/// DG1 buffer size (a TD1 MRZ with its tags is 95 bytes).
pub global DG1_MAX: u32 = 95;
/// Header and 4 DG1 fields, padded to whole blocks of 3.
pub global PLAINTEXT_FIELDS: u32 = 6;
/// "eid-envelope/wrap/v1" as a big-endian integer.
pub global WRAP_DOMAIN: Field = 0x6569642d656e76656c6f70652f777261702f7631;
/// "eid-envelope/cipher/v1" as a big-endian integer.
pub global CIPHER_DOMAIN: Field = 0x6569642d656e76656c6f70652f6369706865722f7631;
/// "eid-nullifier/v1" as a big-endian integer.
pub global NULLIFIER_DOMAIN: Field = 0x6569642d6e756c6c69666965722f7631;

/// What a proof publishes.
pub struct Envelope {
    /// `E = e·G`.
    pub ephemeral: EmbeddedCurvePoint,
    /// `K + kᵢ` per viewer slot.
    pub wrapped: [Field; VIEWERS],
    pub ciphertext: [Field; PLAINTEXT_FIELDS],
}

/// The plaintext: `dg1_len`, then `pack_be(dg1)` over the whole zero-padded
/// buffer, then a zero. The caller asserts the buffer is zero past `dg1_len`.
pub fn plaintext(dg1: [u8; DG1_MAX], dg1_len: u32) -> [Field; PLAINTEXT_FIELDS] {
    let a: [Field; 4] = pack_be(dg1);
    let mut out: [Field; PLAINTEXT_FIELDS] = [0; PLAINTEXT_FIELDS];
    out[0] = dg1_len as Field;
    for i in 0..4 {
        out[1 + i] = a[i];
    }
    out
}

/// The document's nullifier in `scope`: `H(NULLIFIER, scope, digest_len,
/// pack_be(digest))` over the SOD's messageDigest, zero-padded to 64 bytes.
/// The same document gives the same value in one scope and unrelated values
/// across scopes. Scope 0 gives 0: no Sybil check, nothing to link.
pub fn nullifier(scope: Field, digest: [u8; 64], digest_len: u32) -> Field {
    if scope == 0 {
        0
    } else {
        let d: [Field; 3] = pack_be(digest);
        hash(
            [NULLIFIER_DOMAIN, scope, digest_len as Field, d[0], d[1], d[2]],
        )
    }
}

/// Seals `plaintext` under data key `key` with ephemeral scalar `e`, wrapping
/// `key` to the viewer key, which must not be the point at infinity. `context`
/// binds the ciphertext to one use (for example the transfer it travels
/// with): it is absorbed before encryption, so the same plaintext and keys
/// under another context give an unrelated ciphertext.
///
/// `e` and `key` must be fresh and uniformly random per envelope; `e ≠ 0` is
/// asserted. The viewer key is a public input: the receiver's, issued fresh
/// for each transfer (a reused key links transfers).
pub fn seal(
    viewers: [EmbeddedCurvePoint; VIEWERS],
    e: Field,
    key: Field,
    context: Field,
    plaintext: [Field; PLAINTEXT_FIELDS],
) -> Envelope {
    assert(e != 0, "ephemeral scalar must not be zero");
    let s = EmbeddedCurveScalar::from_field(e);
    let ephemeral = fixed_base_scalar_mul(s);

    let mut wrapped: [Field; VIEWERS] = [0; VIEWERS];
    for i in 0..VIEWERS {
        assert(!viewers[i].is_infinite(), "viewer key must not be the point at infinity");
        let shared = multi_scalar_mul([viewers[i]], [s]);
        let k = hash([WRAP_DOMAIN, shared.x, shared.y, i as Field]);
        wrapped[i] = key + k;
    }

    let mut state: [Field; 4] =
        std::hash::poseidon2_permutation([key, ephemeral.x, ephemeral.y, CIPHER_DOMAIN]);
    state[0] += context;
    state = std::hash::poseidon2_permutation(state);
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
