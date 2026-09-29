//! Step C (document): the eContent that step B's messageDigest commits to
//! lists the hash of the DG1 the prover holds, the document has not expired
//! at the proof date, its issuing state is the registry leaf's country, and
//! the step leaves a hiding commitment to DG1's plaintext (a channel payload,
//! zk-encryption's `channel::payload::commit`) for an envelope app to open
//! and seal. DG11 isn't used (see docs/circuits/document.md).
//!
//! The binary for each (eContent hash, data group hash, eContent bucket)
//! does, in this order:
//! 1. `let p = document::check(date, w, hash_oid)`, which walks the LDS
//!    security object and DG1 and runs the date and country checks (below);
//! 2. hashes the eContent with its eContent hash and calls
//!    `assert_message_digest`, then hashes DG1 with its data group hash and
//!    calls `assert_hash_at` on the listed hash;
//! 3. returns `document::outputs(...)`: `[c_B, payload_commitment, date,
//!    scope, nullifier]`.

use channel::payload::commit;
use csca_registry::country_from_mrz;
use csca_registry::{hash, pack_be};
use eid_der::{assert_zero_padded, days_from_civil, expect, Lds, parse_lds, SignedAttrs};

/// DG1 buffer size (a TD1 MRZ with its tags is 95 bytes).
pub global DG1_MAX: u32 = 95;
/// The payload: DG1's length and 4 packed fields, padded to six (zk-encryption's `Payload<6>`).
pub global PAYLOAD_FIELDS: u32 = 6;
/// "eid-nullifier/v1" as a big-endian integer.
pub global NULLIFIER_DOMAIN: Field = 0x6569642d6e756c6c69666965722f7631;
/// The document step's record: `[c_B, payload_commitment, date, scope, nullifier]`.
pub global OUTPUT_FIELDS: u32 = 5;

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

/// The payload an envelope app seals: `dg1_len`, then `pack_be(dg1)` over
/// the whole zero-padded buffer, then a zero. `check` asserts the buffer is
/// zero past `dg1_len`.
pub fn plaintext(dg1: [u8; DG1_MAX], dg1_len: u32) -> [Field; PAYLOAD_FIELDS] {
    let a: [Field; 4] = pack_be(dg1);
    let mut out: [Field; PAYLOAD_FIELDS] = [0; PAYLOAD_FIELDS];
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

/// Runs the document step checks besides hashing:
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

/// Step C's record: step B's commitment recomputed from the witness, the
/// hiding commitment to DG1's payload under `dg1_salt` (the link an
/// envelope app continues), the proof date, the scope and the nullifier of
/// the messageDigest in `scope`.
pub fn outputs<let E: u32>(
    date: u64,
    scope: Field,
    dg1_salt: Field,
    w: Witness<E>,
    p: Parsed,
) -> [Field; OUTPUT_FIELDS] {
    let attrs = SignedAttrs { len: 0, digest: w.digest, digest_len: w.digest_len };
    [
        crate::sod::commitment(w.sod_salt, w.country, attrs),
        commit(dg1_salt, plaintext(w.dg1, p.dg1.len)),
        date as Field,
        scope,
        nullifier(scope, w.digest, w.digest_len),
    ]
}
