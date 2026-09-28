//! Step C (envelope): the eContent that step B's messageDigest commits to
//! lists the hash of the DG1 being encrypted, the document has not expired
//! at the proof date, its issuing state is the registry leaf's country, and
//! the envelope encrypts exactly that DG1. DG11 isn't used (see
//! docs/circuits/envelope.md).
//!
//! The binary for each (eContent hash, data group hash, eContent bucket)
//! does, in this order:
//! 1. `let p = envelope::check(date, w, hash_oid)`, which walks the LDS
//!    security object and DG1 and runs the date and country checks (below);
//! 2. hashes the eContent with its eContent hash and calls
//!    `assert_message_digest`, then hashes DG1 with its data group hash and
//!    calls `assert_hash_at` on the listed hash;
//! 3. returns `envelope::outputs(...)`.

use csca_registry::country_from_mrz;
use eid_der::{assert_zero_padded, days_from_civil, expect, Lds, parse_lds, SignedAttrs};
use eid_envelope::{DG1_MAX, Envelope, nullifier, plaintext, seal, VIEWERS};
use std::embedded_curve_ops::EmbeddedCurvePoint;

/// Hash algorithm OIDs (whole TLV) as an LDS security object names them.
pub global OID_SHA1: [u8; 7] = [0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a];
pub global OID_SHA224: [u8; 11] =
    [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04];
pub global OID_SHA256: [u8; 11] =
    [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
pub global OID_SHA384: [u8; 11] =
    [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
pub global OID_SHA512: [u8; 11] =
    [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];

/// Private inputs of the envelope step.
pub struct Witness<let E: u32> {
    /// Step B's commitment preimage: salt, country and messageDigest
    /// (zero-padded to 64 bytes).
    pub sod_salt: Field,
    pub country: [u8; 3],
    pub digest: [u8; 64],
    pub digest_len: u32,
    /// The SOD's eContent (LDS security object), zero-padded to the bucket.
    pub econtent: [u8; E],
    /// Offset of the DG1 entry in its dataGroupHashValues.
    pub dg1_offset: u32,
    /// DG1 as read from the chip, zero-padded.
    pub dg1: [u8; DG1_MAX],
    /// Ephemeral Grumpkin scalar and data key: fresh and random per envelope.
    pub ephemeral: Field,
    pub key: Field,
}

/// Fields of DG1 the statement uses.
pub struct Dg1 {
    /// Length of DG1 with its tags.
    pub len: u32,
    /// Issuing state as written in the MRZ (e.g. `D<<`).
    pub issuing_state: [u8; 3],
    /// Last second of the date of expiry, unix seconds (UTC).
    pub expires: u64,
}

/// What `check` returns to the circuit.
pub struct Parsed {
    pub lds: Lds,
    pub dg1: Dg1,
}

/// Public outputs of the envelope step.
pub struct Outputs {
    /// Must equal step B's SOD commitment.
    pub sod_commitment: Field,
    /// Hash ids of the eContent digest and the data group hashes.
    pub econtent_hash_id: Field,
    pub dg_hash_id: Field,
    pub envelope: Envelope,
    /// The document's nullifier in the proof's scope (0 for scope 0).
    pub nullifier: Field,
}

fn digit(b: u8) -> u64 {
    assert((b >= 0x30) & (b <= 0x39), "MRZ date digit expected");
    (b - 0x30) as u64
}

/// Parses DG1: `61 L 5F1F L' MRZ` with an 88-character (TD3, passports),
/// 72-character (TD2) or 90-character (TD1, ID cards) MRZ, zero-padded.
/// The date of expiry is YYMMDD, read as 20YY.
pub fn parse_dg1(dg1: [u8; DG1_MAX]) -> Dg1 {
    let outer = expect(dg1, 0, DG1_MAX, 0x61);
    let len = outer.end(0);
    assert_eq(outer.header_len, 2, "DG1 must use a short length");
    assert_zero_padded(dg1, len);
    assert_eq(dg1[2], 0x5f, "DG1 must hold the MRZ (5F1F)");
    assert_eq(dg1[3], 0x1f, "DG1 must hold the MRZ (5F1F)");
    let mrz_len = dg1[4] as u32;
    assert_eq(mrz_len + 3, outer.len, "MRZ length does not match DG1");
    // Offset of the date of expiry in the MRZ, by format.
    let expiry_at = if mrz_len == 88 {
        65
    } else if mrz_len == 72 {
        57
    } else {
        assert_eq(mrz_len, 90, "MRZ must be TD1, TD2 or TD3");
        38
    };
    let mrz = 5;
    let e = mrz + expiry_at;
    let year = 2000 + digit(dg1[e]) * 10 + digit(dg1[e + 1]);
    let month = digit(dg1[e + 2]) * 10 + digit(dg1[e + 3]);
    let day = digit(dg1[e + 4]) * 10 + digit(dg1[e + 5]);
    let expires = days_from_civil(year, month, day) * 86400 + 86399;
    Dg1 { len, issuing_state: [dg1[mrz + 2], dg1[mrz + 3], dg1[mrz + 4]], expires }
}

/// Runs the envelope step checks besides hashing:
/// - the eContent is an LDS security object with data group hashes under
///   `hash_oid` (`D` bytes each), followed only by zeros, listing DG1 at
///   `dg1_offset`;
/// - DG1 parses, its issuing state normalises to `country`, and it has not
///   expired at `date` (unix seconds).
pub fn check<let E: u32, let O: u32, let D: u32>(
    date: u64,
    w: Witness<E>,
    hash_oid: [u8; O],
) -> Parsed {
    let lds: Lds = parse_lds::<E, O, D>(w.econtent, hash_oid, w.dg1_offset);
    assert_zero_padded(w.econtent, lds.len);
    let dg1 = parse_dg1(w.dg1);
    assert_eq(
        country_from_mrz(dg1.issuing_state),
        w.country,
        "issuing state does not match the registry country",
    );
    assert(date <= dg1.expires, "document has expired at the given date");
    Parsed { lds, dg1 }
}

/// Asserts step B's messageDigest is `computed`, the eContent's hash.
pub fn assert_message_digest<let E: u32, let D: u32>(w: Witness<E>, computed: [u8; D]) {
    assert_eq(w.digest_len, D, "messageDigest length does not match the eContent hash");
    for i in 0..D {
        assert_eq(w.digest[i], computed[i], "messageDigest does not match the eContent");
    }
}

/// Asserts `buf[at..at + D] == digest`.
pub fn assert_hash_at<let N: u32, let D: u32>(buf: [u8; N], at: u32, digest: [u8; D]) {
    for i in 0..D {
        assert_eq(buf[at + i], digest[i], "data group hash does not match the LDS security object");
    }
}

/// Step C outputs: step B's commitment recomputed from the witness, the hash
/// ids, the envelope of DG1 to `viewers`, bound to `context`, and the
/// nullifier of the messageDigest in `scope`.
pub fn outputs<let E: u32>(
    viewers: [EmbeddedCurvePoint; VIEWERS],
    context: Field,
    scope: Field,
    w: Witness<E>,
    p: Parsed,
    econtent_hash_id: u8,
    dg_hash_id: u8,
) -> Outputs {
    let attrs = SignedAttrs { len: 0, digest: w.digest, digest_len: w.digest_len };
    let pt = plaintext(w.dg1, p.dg1.len);
    Outputs {
        sod_commitment: crate::sod::commitment(w.sod_salt, w.country, attrs),
        econtent_hash_id: econtent_hash_id as Field,
        dg_hash_id: dg_hash_id as Field,
        envelope: seal(viewers, w.ephemeral, w.key, context, pt),
        nullifier: nullifier(scope, w.digest, w.digest_len),
    }
}

/// Values of the envelope step's databus output: date, context, the viewer
/// keys, `Outputs` (step B's commitment, the hash ids, the envelope), the
/// scope and the nullifier.
pub global OUTPUT_FIELDS: u32 = 18;

/// The envelope step's databus output, flattened in this order: `[date,
/// context, viewer (x, y), sod_commitment, econtent_hash_id, dg_hash_id, E.x,
/// E.y, wrapped, ciphertext × 6, scope, nullifier]`. The envelope kernel
/// reads it back.
pub fn flatten(
    date: u64,
    context: Field,
    scope: Field,
    viewers: [EmbeddedCurvePoint; VIEWERS],
    o: Outputs,
) -> [Field; OUTPUT_FIELDS] {
    let mut out: [Field; OUTPUT_FIELDS] = [0; OUTPUT_FIELDS];
    out[0] = date as Field;
    out[1] = context;
    for i in 0..VIEWERS {
        out[2 + 2 * i] = viewers[i].x;
        out[3 + 2 * i] = viewers[i].y;
    }
    out[4] = o.sod_commitment;
    out[5] = o.econtent_hash_id;
    out[6] = o.dg_hash_id;
    out[7] = o.envelope.ephemeral.x;
    out[8] = o.envelope.ephemeral.y;
    for i in 0..VIEWERS {
        out[9 + i] = o.envelope.wrapped[i];
    }
    for i in 0..6 {
        out[10 + i] = o.envelope.ciphertext[i];
    }
    out[16] = scope;
    out[17] = o.nullifier;
    out
}
