//! Envelope encryption of an eMRTD's DG1 to the receiver's key, byte-for-byte
//! the construction the envelope step circuit (step C) proves. Provers use
//! [`seal`] to build the witness; the receiver uses [`open`] to decrypt what
//! a proof published. Specification: docs/circuits/envelope.md.
//!
//! - **KEM.** An ephemeral Grumpkin scalar `e` gives `E = e·G`. The viewer
//!   key `V` in slot `i` (one slot) gets `kᵢ = H(WRAP, (e·V).x, (e·V).y, i)`
//!   and the data key `K` is published as `K + kᵢ`. The receiver with secret
//!   `v` (`V = v·G`) recomputes `v·E = e·V`.
//! - **DEM.** A Poseidon2 duplex (width 4, rate 3) keyed with
//!   `(K, E.x, E.y, CIPHER)`, then the caller's `context` absorbed: each
//!   ciphertext element is the plaintext plus a state element, and replaces
//!   it before the next permutation.
//! - **Plaintext.** `PLAINTEXT_FIELDS` fields: `dg1_len`, then DG1
//!   zero-padded to `DG1_MAX` bytes and packed like `csca_registry::pack_be`,
//!   then a zero. Its size is fixed. DG11 isn't carried (see
//!   docs/circuits/envelope.md).
//!
//! `H` is Noir's Poseidon2 sponge (`hash_noir`); the permutation is BN254
//! Poseidon2 with t = 4.

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField, Zero};
use pso_poseidon::poseidon2::Poseidon2;

/// BN254 scalar field: Noir's `Field`, and Grumpkin's base field.
pub use ark_bn254::Fr;

/// Viewer slots per envelope.
pub const VIEWERS: usize = 1;
/// DG1 buffer size (TD1 MRZ: 95 bytes with its tags).
pub const DG1_MAX: usize = 95;
/// 31-byte fields for DG1.
pub const DG1_FIELDS: usize = DG1_MAX.div_ceil(31);
/// Header and DG1, padded to whole duplex blocks of 3.
pub const PLAINTEXT_FIELDS: usize = (1 + DG1_FIELDS).div_ceil(3) * 3;

/// Domain tags: the ASCII strings as big-endian integers.
pub fn wrap_domain() -> Fr {
    Fr::from_be_bytes_mod_order(b"eid-envelope/wrap/v1")
}
pub fn cipher_domain() -> Fr {
    Fr::from_be_bytes_mod_order(b"eid-envelope/cipher/v1")
}
pub fn nullifier_domain() -> Fr {
    Fr::from_be_bytes_mod_order(b"eid-nullifier/v1")
}

/// A Grumpkin point in affine coordinates (`None` is the point at infinity).
pub type Point = Option<(Fr, Fr)>;

/// What a proof publishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// `E = e·G`.
    pub ephemeral: (Fr, Fr),
    /// `K + kᵢ` per viewer slot.
    pub wrapped: [Fr; VIEWERS],
    pub ciphertext: [Fr; PLAINTEXT_FIELDS],
}

/// Errors from [`seal`] and [`open`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// DG1 is larger than its buffer.
    TooLong,
    /// The ephemeral scalar is zero.
    ZeroScalar,
    /// A viewer key is not on Grumpkin.
    NotOnCurve,
    /// A viewer slot has no key: every slot must have one.
    NoViewer,
    /// The slot is empty or out of range.
    NoSuchSlot,
    /// The decrypted header or padding is inconsistent (wrong key or slot).
    Malformed,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::TooLong => "data group longer than its buffer",
            Self::ZeroScalar => "ephemeral scalar is zero",
            Self::NotOnCurve => "viewer key is not on Grumpkin",
            Self::NoViewer => "every viewer slot needs a key",
            Self::NoSuchSlot => "no such viewer slot",
            Self::Malformed => "plaintext is malformed (wrong key or slot)",
        })
    }
}

impl std::error::Error for Error {}

/// Noir's Poseidon2 sponge.
pub fn hash(inputs: &[Fr]) -> Fr {
    Poseidon2::<Fr>::new().hash_noir(inputs)
}

fn permute(state: [Fr; 4]) -> [Fr; 4] {
    Poseidon2::<Fr>::new().permutation(&state)
}

/// `s·P` on Grumpkin, `s` read as an integer (every `Fr` is below the
/// Grumpkin group order).
fn mul(s: Fr, p: ark_grumpkin::Affine) -> Point {
    let scalar = ark_grumpkin::Fr::from_le_bytes_mod_order(&s.into_bigint().to_bytes_le());
    let r = (p * scalar).into_affine();
    r.xy()
}

fn affine(p: (Fr, Fr)) -> Result<ark_grumpkin::Affine, Error> {
    let a = ark_grumpkin::Affine::new_unchecked(p.0, p.1);
    if a.is_on_curve() && a.is_in_correct_subgroup_assuming_on_curve() {
        Ok(a)
    } else {
        Err(Error::NotOnCurve)
    }
}

/// The public key for a viewer secret: `v·G`.
pub fn public_key(secret: Fr) -> Point {
    mul(secret, ark_grumpkin::Affine::generator())
}

/// Big-endian 31-byte chunks of `bytes`, least significant chunk first
/// (`csca_registry::pack_be`).
pub fn pack_be(bytes: &[u8]) -> Vec<Fr> {
    bytes.rchunks(31).map(Fr::from_be_bytes_mod_order).collect()
}

fn unpack_be(fields: &[Fr], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    for (i, chunk) in out.rchunks_mut(31).enumerate() {
        let be = fields[i].into_bigint().to_bytes_be();
        chunk.copy_from_slice(&be[be.len() - chunk.len()..]);
    }
    out
}

fn padded(bytes: &[u8], len: usize) -> Result<Vec<u8>, Error> {
    if bytes.len() > len {
        return Err(Error::TooLong);
    }
    let mut v = bytes.to_vec();
    v.resize(len, 0);
    Ok(v)
}

/// The plaintext field elements for DG1.
pub fn plaintext(dg1: &[u8]) -> Result<[Fr; PLAINTEXT_FIELDS], Error> {
    let mut out = [Fr::zero(); PLAINTEXT_FIELDS];
    out[0] = Fr::from(dg1.len() as u64);
    out[1..=DG1_FIELDS].copy_from_slice(&pack_be(&padded(dg1, DG1_MAX)?));
    Ok(out)
}

/// Runs the duplex over `input`; `encrypt` selects which side `input` is.
fn duplex(
    key: Fr,
    eph: (Fr, Fr),
    context: Fr,
    input: &[Fr; PLAINTEXT_FIELDS],
    encrypt: bool,
) -> [Fr; PLAINTEXT_FIELDS] {
    let mut state = permute([key, eph.0, eph.1, cipher_domain()]);
    state[0] += context;
    state = permute(state);
    let mut out = [Fr::zero(); PLAINTEXT_FIELDS];
    for (inp, outp) in input.chunks(3).zip(out.chunks_mut(3)) {
        for (j, s) in state.iter_mut().take(3).enumerate() {
            let c = if encrypt { inp[j] + *s } else { inp[j] };
            outp[j] = if encrypt { c } else { inp[j] - *s };
            *s = c;
        }
        state = permute(state);
    }
    out
}

fn slot_key(shared: (Fr, Fr), slot: usize) -> Fr {
    hash(&[wrap_domain(), shared.0, shared.1, Fr::from(slot as u64)])
}

/// Encrypts DG1 to `VIEWERS` keys (each required; the client uses a fresh
/// viewer key per transfer) with ephemeral scalar `e` and data key `key`, both fresh and
/// uniformly random per envelope. `context` binds the envelope to one use
/// (the step C public input of the same name); viewers need it to open.
pub fn seal(
    dg1: &[u8],
    viewers: &[Point; VIEWERS],
    e: Fr,
    key: Fr,
    context: Fr,
) -> Result<Envelope, Error> {
    if e.is_zero() {
        return Err(Error::ZeroScalar);
    }
    let eph = public_key(e).ok_or(Error::ZeroScalar)?;
    let mut wrapped = [Fr::zero(); VIEWERS];
    for (i, v) in viewers.iter().enumerate() {
        let v = v.ok_or(Error::NoViewer)?;
        let shared = mul(e, affine(v)?).ok_or(Error::NotOnCurve)?;
        wrapped[i] = key + slot_key(shared, i);
    }
    let ciphertext = duplex(key, eph, context, &plaintext(dg1)?, true);
    Ok(Envelope {
        ephemeral: eph,
        wrapped,
        ciphertext,
    })
}

/// The document's nullifier in `scope`, as step C outputs it:
/// `H(NULLIFIER, scope, digest_len, pack_be(digest))` over the SOD's
/// messageDigest zero-padded to 64 bytes, or 0 when `scope` is 0.
pub fn nullifier(scope: Fr, digest: &[u8]) -> Result<Fr, Error> {
    if scope.is_zero() {
        return Ok(Fr::zero());
    }
    let mut inputs = vec![nullifier_domain(), scope, Fr::from(digest.len() as u64)];
    inputs.extend(pack_be(&padded(digest, 64)?));
    Ok(hash(&inputs))
}

/// Decrypts `env`, sealed under `context`, as the viewer in `slot` with
/// secret `v`. Returns DG1.
pub fn open(env: &Envelope, context: Fr, slot: usize, v: Fr) -> Result<Vec<u8>, Error> {
    let wrapped = *env.wrapped.get(slot).ok_or(Error::NoSuchSlot)?;
    if wrapped.is_zero() {
        return Err(Error::NoSuchSlot);
    }
    let shared = mul(v, affine(env.ephemeral)?).ok_or(Error::Malformed)?;
    let key = wrapped - slot_key(shared, slot);
    let p = duplex(key, env.ephemeral, context, &env.ciphertext, false);
    let header = p[0].into_bigint().to_bytes_le();
    let dg1_len = usize::from(header[0]);
    if header[1..].iter().any(|b| *b != 0) || dg1_len > DG1_MAX {
        return Err(Error::Malformed);
    }
    let dg1 = unpack_be(&p[1..=DG1_FIELDS], DG1_MAX);
    if dg1[dg1_len..].iter().any(|x| *x != 0) || p[1 + DG1_FIELDS..].iter().any(|f| !f.is_zero()) {
        return Err(Error::Malformed);
    }
    Ok(dg1[..dg1_len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::MontFp;

    #[test]
    fn nullifier_is_scoped() {
        let d = [7u8; 32];
        assert_eq!(nullifier(Fr::zero(), &d), Ok(Fr::zero()));
        let a = nullifier(Fr::from(5u64), &d).unwrap();
        assert!(!a.is_zero());
        assert_eq!(nullifier(Fr::from(5u64), &d), Ok(a));
        assert_ne!(nullifier(Fr::from(6u64), &d), Ok(a));
        assert_eq!(nullifier(Fr::from(5u64), &[0; 65]), Err(Error::TooLong));
    }

    #[test]
    fn matches_noir_primitives() {
        // `nargo test` values: 2·G on Grumpkin, and the permutation of [1, 2, 3, 4].
        let (x, _) = public_key(Fr::from(2u64)).unwrap();
        let expected: Fr =
            MontFp!("0x06ce1b0827aafa85ddeb49cdaa36306d19a74caa311e13d46d8bc688cdbffffe");
        assert_eq!(x, expected);
        let st = permute([
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        ]);
        let s0: Fr = MontFp!("0x224785a48a72c75e2cbb698143e71d5d41bd89a2b9a7185871e39a54ce5785b1");
        assert_eq!(st[0], s0);
    }

    #[test]
    fn sizes() {
        assert_eq!((DG1_FIELDS, PLAINTEXT_FIELDS), (4, 6));
    }

    #[test]
    fn round_trip() {
        let secrets = [Fr::from(11u64), Fr::from(22u64)];
        let viewers = [public_key(secrets[0])];
        let dg1 = [0x61u8; 93];
        let env = seal(
            &dg1,
            &viewers,
            Fr::from(5u64),
            Fr::from(7u64),
            Fr::from(99u64),
        )
        .unwrap();
        assert_eq!(open(&env, Fr::from(99u64), 0, secrets[0]).unwrap(), dg1);
        assert_eq!(
            open(&env, Fr::from(99u64), 1, secrets[0]),
            Err(Error::NoSuchSlot)
        );
        // The slot must have a key.
        assert_eq!(
            seal(
                &dg1,
                &[None],
                Fr::from(5u64),
                Fr::from(7u64),
                Fr::from(99u64)
            ),
            Err(Error::NoViewer)
        );
        assert_eq!(
            open(&env, Fr::from(99u64), 0, secrets[1]),
            Err(Error::Malformed)
        );
        // Another context does not decrypt.
        assert_eq!(
            open(&env, Fr::from(98u64), 0, secrets[0]),
            Err(Error::Malformed)
        );
    }

    #[test]
    fn short_dg1_and_limits() {
        let v = [public_key(Fr::from(3u64))];
        let env = seal(
            &[1, 2, 3],
            &v,
            Fr::from(9u64),
            Fr::from(4u64),
            Fr::from(99u64),
        )
        .unwrap();
        assert_eq!(
            open(&env, Fr::from(99u64), 0, Fr::from(3u64)).unwrap(),
            vec![1, 2, 3]
        );
        assert_eq!(
            seal(
                &[0; 96],
                &v,
                Fr::from(9u64),
                Fr::from(4u64),
                Fr::from(99u64)
            ),
            Err(Error::TooLong)
        );
        assert_eq!(
            seal(&[1], &v, Fr::zero(), Fr::from(4u64), Fr::from(99u64)),
            Err(Error::ZeroScalar)
        );
        let off = [Some((Fr::from(1u64), Fr::from(1u64)))];
        assert_eq!(
            seal(&[1], &off, Fr::from(9u64), Fr::from(4u64), Fr::from(99u64)),
            Err(Error::NotOnCurve)
        );
    }

    #[test]
    fn packing_matches_csca_registry() {
        // 33 bytes: front 2-byte chunk is the most significant field (index 1).
        let bytes: Vec<u8> = (1..=33).collect();
        let f = pack_be(&bytes);
        assert_eq!(f[1], Fr::from(0x0102u64));
        assert_eq!(f[0], Fr::from_be_bytes_mod_order(&bytes[2..]));
        assert_eq!(unpack_be(&f, 33), bytes);
    }
}
