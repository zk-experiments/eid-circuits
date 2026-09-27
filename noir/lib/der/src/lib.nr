//! Constrained DER reading for X.509 TBSCertificates, their public keys, and
//! CMS signed attributes. Every value read here is constrained against the buffer: a
//! prover cannot point a field at bytes that do not encode it.
//! Specification and review notes: README.md.

pub mod curves;
mod tests;
mod vectors;

/// Tags used by the certificate walk.
pub global TAG_SEQUENCE: u8 = 0x30;
pub global TAG_INTEGER: u8 = 0x02;
pub global TAG_UTC_TIME: u8 = 0x17;
pub global TAG_GENERALIZED_TIME: u8 = 0x18;
pub global TAG_CONTEXT_0: u8 = 0xa0;
pub global TAG_BIT_STRING: u8 = 0x03;
pub global TAG_OCTET_STRING: u8 = 0x04;
pub global TAG_SET: u8 = 0x31;

/// `06 09 2A 86 48 86 F7 0D 01 01`: the rsaEncryption (`…01 01 01`) and
/// id-RSASSA-PSS (`…01 01 0A`) OIDs without their last byte.
global OID_RSA_PREFIX: [u8; 10] = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01];
/// `06 07 2A 86 48 CE 3D 02 01`: id-ecPublicKey.
global OID_EC_PUBLIC_KEY: [u8; 9] = [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// `06 07 2A 86 48 CE 3D 01 01`: prime-field.
global OID_PRIME_FIELD: [u8; 9] = [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x01, 0x01];
/// `06 09 2A 86 48 86 F7 0D 01 09 04`: id-messageDigest.
global OID_MESSAGE_DIGEST: [u8; 11] =
    [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];
/// Attributes walked in a SignerInfo's signedAttrs (eMRTDs carry 2 to 4).
pub global MAX_SIGNED_ATTRS: u32 = 8;
/// Data groups an LDS security object can list (DG1 to DG16).
pub global MAX_DATA_GROUPS: u32 = 16;

/// A TLV header read at some offset: the content starts at
/// `offset + header_len` and is `len` bytes long.
pub struct Header {
    pub tag: u8,
    pub header_len: u32,
    pub len: u32,
}

impl Header {
    /// Offset just past this element, given where its header started.
    pub fn end(self, offset: u32) -> u32 {
        offset + self.header_len + self.len
    }
}

/// Reads the DER header at `offset` and asserts the element ends within the
/// first `limit` bytes. Supports single-byte tags and definite lengths up to
/// 65535 (short form, `0x81 L`, `0x82 L L`), and rejects non-minimal long
/// forms as DER requires.
pub fn read<let N: u32>(der: [u8; N], offset: u32, limit: u32) -> Header {
    assert(limit <= N, "DER limit exceeds buffer");
    let tag = der[offset];
    let l0 = der[offset + 1];
    let mut header_len: u32 = 2;
    let mut len: u32 = l0 as u32;
    if l0 == 0x81 {
        let l1 = der[offset + 2] as u32;
        assert(l1 >= 0x80, "non-minimal DER length");
        header_len = 3;
        len = l1;
    } else if l0 == 0x82 {
        let l1 = der[offset + 2] as u32;
        let l2 = der[offset + 3] as u32;
        assert(l1 != 0, "non-minimal DER length");
        header_len = 4;
        len = l1 * 256 + l2;
    } else {
        assert(l0 < 0x80, "unsupported DER length form");
    }
    assert(offset + header_len + len <= limit, "DER element exceeds its container");
    Header { tag, header_len, len }
}

/// Reads the header at `offset` and asserts its tag.
pub fn expect<let N: u32>(der: [u8; N], offset: u32, limit: u32, tag: u8) -> Header {
    let h = read(der, offset, limit);
    assert_eq(h.tag, tag, "unexpected DER tag");
    h
}

/// Asserts `der[offset..offset + L] == expected`.
pub fn assert_bytes<let N: u32, let L: u32>(der: [u8; N], offset: u32, expected: [u8; L]) {
    for i in 0..L {
        assert_eq(der[offset + i], expected[i], "unexpected DER bytes");
    }
}

/// The non-negative INTEGER at `offset`, right-aligned in `L` bytes, and the
/// offset past it. The encoding must be minimal (a leading 0x00 only when the
/// next byte has its top bit set) and the value must fit `L` bytes.
pub fn read_uint<let N: u32, let L: u32>(der: [u8; N], offset: u32, limit: u32) -> ([u8; L], u32) {
    let h = expect(der, offset, limit, TAG_INTEGER);
    let start = offset + h.header_len;
    assert(h.len >= 1, "empty INTEGER");
    assert(der[start] < 0x80, "negative INTEGER");
    if (h.len > 1) & (der[start] == 0) {
        assert(der[start + 1] >= 0x80, "non-minimal INTEGER");
    }
    let skip = if (h.len > 1) & (der[start] == 0) {
        1
    } else {
        0
    };
    assert(h.len - skip <= L, "INTEGER does not fit");
    let end = start + h.len;
    let mut out: [u8; L] = [0; L];
    for i in 0..L {
        // out[i] is the byte L - i positions before `end`, when inside the value.
        if end + i >= start + skip + L {
            out[i] = der[end + i - L];
        }
    }
    (out, h.end(offset))
}

/// The INTEGER at `offset` as a positive big-endian value right-aligned in 20
/// bytes (RFC 5280 serials are at most 20 octets; a leading 0x00 that keeps
/// the value positive is allowed as a 21st). Negative values are rejected.
pub fn read_serial<let N: u32>(der: [u8; N], offset: u32, limit: u32) -> ([u8; 20], u32) {
    let h = expect(der, offset, limit, TAG_INTEGER);
    let start = offset + h.header_len;
    assert((h.len >= 1) & (h.len <= 21), "serial must be 1 to 21 bytes");
    assert(der[start] < 0x80, "negative serial");
    if h.len == 21 {
        assert_eq(der[start], 0, "21-byte serial must start with 0x00");
    }
    let end = start + h.len;
    let mut out: [u8; 20] = [0; 20];
    for i in 0..20 {
        // out[i] is the byte 20 - i positions before `end`, when inside the value.
        let src = end + i;
        if src >= start + 20 {
            out[i] = der[src - 20];
        }
    }
    (out, h.end(offset))
}

fn digit<let N: u32>(der: [u8; N], at: u32) -> u64 {
    let c = der[at];
    assert((c >= 0x30) & (c <= 0x39), "time digit expected");
    (c - 0x30) as u64
}

fn two<let N: u32>(der: [u8; N], at: u32) -> u64 {
    digit(der, at) * 10 + digit(der, at + 1)
}

/// Days since 1970-01-01 for a proleptic Gregorian date in 1970..9999
/// (H. Hinnant's days_from_civil, restricted to non-negative eras).
pub fn days_from_civil(year: u64, month: u64, day: u64) -> u64 {
    assert((month >= 1) & (month <= 12) & (day >= 1) & (day <= 31), "invalid date");
    assert(year >= 1970, "dates before 1970 are not supported");
    let y = if month <= 2 { year - 1 } else { year };
    let era = y / 400;
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// The X.509 `Time` at `offset` as unix seconds: UTCTime `YYMMDDHHMMSSZ`
/// (years 50–99 are 19xx, 00–49 are 20xx, RFC 5280 §4.1.2.5.1) or
/// GeneralizedTime `YYYYMMDDHHMMSSZ`. Fractions and offsets are rejected, as
/// RFC 5280 requires.
pub fn read_time<let N: u32>(der: [u8; N], offset: u32, limit: u32) -> (u64, u32) {
    let h = read(der, offset, limit);
    let s = offset + h.header_len;
    let mut year: u64 = 0;
    let mut p = s;
    if h.tag == TAG_UTC_TIME {
        assert_eq(h.len, 13, "UTCTime must be YYMMDDHHMMSSZ");
        let yy = two(der, s);
        year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
        p = s + 2;
    } else {
        assert_eq(h.tag, TAG_GENERALIZED_TIME, "Time must be UTCTime or GeneralizedTime");
        assert_eq(h.len, 15, "GeneralizedTime must be YYYYMMDDHHMMSSZ");
        year = two(der, s) * 100 + two(der, s + 2);
        p = s + 4;
    }
    let month = two(der, p);
    let day = two(der, p + 2);
    let hour = two(der, p + 4);
    let minute = two(der, p + 6);
    let second = two(der, p + 8);
    assert_eq(der[p + 10], 0x5a, "Time must end in Z");
    assert((hour < 24) & (minute < 60) & (second < 60), "invalid time of day");
    let t = days_from_civil(year, month, day) * 86400 + hour * 3600 + minute * 60 + second;
    (t, h.end(offset))
}

/// Fields of a TBSCertificate the circuits need.
pub struct TbsFields {
    /// DER length of the whole TBSCertificate (header included).
    pub len: u32,
    /// serialNumber, right-aligned in 20 bytes.
    pub serial: [u8; 20],
    /// validity.notBefore, unix seconds.
    pub not_before: u64,
    /// validity.notAfter, unix seconds.
    pub not_after: u64,
    /// Offset of subjectPublicKeyInfo.
    pub spki_offset: u32,
}

/// Walks `TBSCertificate ::= SEQUENCE { [0] version, serialNumber,
/// signature, issuer, validity, subject, subjectPublicKeyInfo, … }` from
/// offset 0 of `tbs`. The length comes from the outer header and must fit the
/// buffer; every bound checks against it.
pub fn parse_tbs<let N: u32>(tbs: [u8; N]) -> TbsFields {
    let outer = expect(tbs, 0, N, TAG_SEQUENCE);
    let len = outer.end(0);
    let mut o = outer.header_len;
    // version [0] EXPLICIT: DSCs are v3; the element is required here.
    let version = expect(tbs, o, len, TAG_CONTEXT_0);
    o = version.end(o);
    let (serial, after_serial) = read_serial(tbs, o, len);
    o = after_serial;
    // signature AlgorithmIdentifier, issuer Name
    o = expect(tbs, o, len, TAG_SEQUENCE).end(o);
    o = expect(tbs, o, len, TAG_SEQUENCE).end(o);
    let validity = expect(tbs, o, len, TAG_SEQUENCE);
    let vo = o + validity.header_len;
    let (not_before, after_nb) = read_time(tbs, vo, validity.end(o));
    let (not_after, after_na) = read_time(tbs, after_nb, validity.end(o));
    assert_eq(after_na, validity.end(o), "validity must hold exactly two times");
    o = validity.end(o);
    // subject Name
    o = expect(tbs, o, len, TAG_SEQUENCE).end(o);
    let spki = expect(tbs, o, len, TAG_SEQUENCE);
    let _ = spki;
    TbsFields { len, serial, not_before, not_after, spki_offset: o }
}

/// Reads the RSA `SubjectPublicKeyInfo` at `offset`:
/// `SEQUENCE { SEQUENCE { rsaEncryption | id-RSASSA-PSS, params }, BIT STRING
/// { 0x00, SEQUENCE { INTEGER n, INTEGER e } } }`. Returns the modulus
/// right-aligned in `K` bytes and the exponent (at most 4 bytes). A shorter
/// modulus comes back with leading zeros; the RSA library rejects it.
pub fn spki_rsa<let N: u32, let K: u32>(der: [u8; N], offset: u32, limit: u32) -> ([u8; K], u32) {
    let spki = expect(der, offset, limit, TAG_SEQUENCE);
    let end = spki.end(offset);
    let alg_at = offset + spki.header_len;
    let alg = expect(der, alg_at, end, TAG_SEQUENCE);
    let oid_at = alg_at + alg.header_len;
    assert_bytes(der, oid_at, OID_RSA_PREFIX);
    let last = der[oid_at + 10];
    assert((last == 0x01) | (last == 0x0a), "key is not RSA");
    let bits_at = alg.end(alg_at);
    let bits = expect(der, bits_at, end, TAG_BIT_STRING);
    assert_eq(bits.end(bits_at), end, "trailing bytes in SubjectPublicKeyInfo");
    assert_eq(der[bits_at + bits.header_len], 0, "BIT STRING has unused bits");
    let key_at = bits_at + bits.header_len + 1;
    let key = expect(der, key_at, end, TAG_SEQUENCE);
    assert_eq(key.end(key_at), end, "trailing bytes in RSAPublicKey");
    let (modulus, after_n): ([u8; K], u32) = read_uint(der, key_at + key.header_len, end);
    let (e, after_e): ([u8; 4], u32) = read_uint(der, after_n, end);
    assert_eq(after_e, end, "trailing bytes in RSAPublicKey");
    let exponent =
        ((e[0] as u32) << 24) | ((e[1] as u32) << 16) | ((e[2] as u32) << 8) | (e[3] as u32);
    (modulus, exponent)
}

/// The prime-field curve a circuit verifies on: its named-curve OID (whole
/// TLV) and the `p`, `a`, `b` a certificate with explicit parameters must
/// carry. ECDSA then checks the point is on this curve.
pub struct Curve<let S: u32, let O: u32> {
    pub oid: [u8; O],
    pub p: [u8; S],
    pub a: [u8; S],
    pub b: [u8; S],
}

/// Reads the EC `SubjectPublicKeyInfo` at `offset`: `SEQUENCE { SEQUENCE {
/// id-ecPublicKey, params }, BIT STRING { 0x00, 0x04 ‖ x ‖ y } }`. `params`
/// is either the named-curve OID, which must equal `curve.oid`, or explicit
/// `ECParameters` (ICAO 9303 requires these) whose prime and coefficients
/// must equal `curve`'s. Returns `(x, y)`.
pub fn spki_ec<let N: u32, let S: u32, let O: u32>(
    der: [u8; N],
    offset: u32,
    limit: u32,
    curve: Curve<S, O>,
) -> ([u8; S], [u8; S]) {
    let spki = expect(der, offset, limit, TAG_SEQUENCE);
    let end = spki.end(offset);
    let alg_at = offset + spki.header_len;
    let alg = expect(der, alg_at, end, TAG_SEQUENCE);
    let alg_end = alg.end(alg_at);
    let oid_at = alg_at + alg.header_len;
    assert_bytes(der, oid_at, OID_EC_PUBLIC_KEY);
    let params_at = oid_at + 9;
    if der[params_at] == 0x06 {
        assert_bytes(der, params_at, curve.oid);
        assert_eq(params_at + O, alg_end, "trailing bytes after the curve OID");
    } else {
        // ECParameters ::= SEQUENCE { version 1, fieldID, curve, base, order, cofactor OPTIONAL }
        let params = expect(der, params_at, alg_end, TAG_SEQUENCE);
        assert_eq(params.end(params_at), alg_end, "trailing bytes after ECParameters");
        let version_at = params_at + params.header_len;
        assert_bytes(der, version_at, [TAG_INTEGER, 0x01, 0x01]);
        let field_at = version_at + 3;
        let field = expect(der, field_at, alg_end, TAG_SEQUENCE);
        assert_bytes(der, field_at + field.header_len, OID_PRIME_FIELD);
        let (p, after_p): ([u8; S], u32) = read_uint(der, field_at + field.header_len + 9, alg_end);
        assert_eq(after_p, field.end(field_at), "trailing bytes in FieldID");
        assert_eq(p, curve.p, "explicit curve prime does not match the circuit");
        let coeffs_at = field.end(field_at);
        let coeffs = expect(der, coeffs_at, alg_end, TAG_SEQUENCE);
        let a_at = coeffs_at + coeffs.header_len;
        let a = expect(der, a_at, coeffs.end(coeffs_at), TAG_OCTET_STRING);
        assert_field_element(der, a_at + a.header_len, a.len, curve.a);
        let b_at = a.end(a_at);
        let b = expect(der, b_at, coeffs.end(coeffs_at), TAG_OCTET_STRING);
        assert_field_element(der, b_at + b.header_len, b.len, curve.b);
    }
    let bits_at = alg_end;
    let bits = expect(der, bits_at, end, TAG_BIT_STRING);
    assert_eq(bits.end(bits_at), end, "trailing bytes in SubjectPublicKeyInfo");
    assert_eq(bits.len, 2 + 2 * S, "EC point must be uncompressed and full size");
    let point_at = bits_at + bits.header_len;
    assert_eq(der[point_at], 0, "BIT STRING has unused bits");
    assert_eq(der[point_at + 1], 0x04, "EC point must be uncompressed");
    let mut x: [u8; S] = [0; S];
    let mut y: [u8; S] = [0; S];
    for i in 0..S {
        x[i] = der[point_at + 2 + i];
        y[i] = der[point_at + 2 + S + i];
    }
    (x, y)
}

/// Asserts the `len` content bytes at `start` are `expected` as a big-endian
/// number. SEC 1 fixes the width at `S` bytes, but issuers also write one
/// extra leading 0x00 (INTEGER style) or drop leading zeros, so any width up
/// to `S + 1` whose value matches is accepted.
fn assert_field_element<let N: u32, let S: u32>(
    der: [u8; N],
    start: u32,
    len: u32,
    expected: [u8; S],
) {
    assert((len >= 1) & (len <= S + 1), "curve coefficient has the wrong length");
    if len == S + 1 {
        assert_eq(der[start], 0, "curve coefficient does not match the circuit");
    }
    let end = start + len;
    for i in 0..S {
        // expected[i] sits S - i bytes before `end`; bytes before `start` are zero.
        if end + i >= start + S {
            assert_eq(
                der[end + i - S],
                expected[i],
                "curve coefficient does not match the circuit",
            );
        } else {
            assert_eq(expected[i], 0, "curve coefficient does not match the circuit");
        }
    }
}

/// CMS signed attributes, as the DSC signs them.
pub struct SignedAttrs {
    /// DER length of the attribute SET (header included).
    pub len: u32,
    /// The messageDigest value, left-aligned and zero-padded.
    pub digest: [u8; 64],
    /// Its length: 20, 28, 32, 48 or 64.
    pub digest_len: u32,
}

/// Walks a SignerInfo's `signedAttrs` in the form that is signed (tag `0x31`,
/// RFC 5652 §5.4) from offset 0: at most `MAX_SIGNED_ATTRS` attributes that
/// exactly fill the SET. `md_offset` must be the start of one of them, and
/// that attribute must be `SEQUENCE { id-messageDigest, SET { OCTET STRING
/// digest } }` with exactly one value.
pub fn parse_signed_attrs<let N: u32>(attrs: [u8; N], md_offset: u32) -> SignedAttrs {
    let set = expect(attrs, 0, N, TAG_SET);
    let len = set.end(0);
    let mut o = set.header_len;
    let mut found = false;
    for _ in 0..MAX_SIGNED_ATTRS {
        if o < len {
            found |= o == md_offset;
            o = expect(attrs, o, len, TAG_SEQUENCE).end(o);
        }
    }
    assert_eq(o, len, "signedAttrs has more attributes than supported");
    assert(found, "md_offset is not the start of an attribute");

    let attr = expect(attrs, md_offset, len, TAG_SEQUENCE);
    let attr_end = attr.end(md_offset);
    assert_bytes(attrs, md_offset + attr.header_len, OID_MESSAGE_DIGEST);
    let values_at = md_offset + attr.header_len + 11;
    let values = expect(attrs, values_at, attr_end, TAG_SET);
    assert_eq(values.end(values_at), attr_end, "trailing bytes in the messageDigest attribute");
    let value_at = values_at + values.header_len;
    let value = expect(attrs, value_at, attr_end, TAG_OCTET_STRING);
    assert_eq(value.end(value_at), attr_end, "messageDigest must have exactly one value");
    let dl = value.len;
    assert(
        (dl == 20) | (dl == 28) | (dl == 32) | (dl == 48) | (dl == 64),
        "messageDigest length is not a SHA digest size",
    );
    let start = value_at + value.header_len;
    let mut digest: [u8; 64] = [0; 64];
    for i in 0..64 {
        // Index 0 in the unused tail keeps every read in bounds.
        let src = if i < dl { start + i } else { 0 };
        let byte = attrs[src];
        digest[i] = if i < dl { byte } else { 0 };
    }
    SignedAttrs { len, digest, digest_len: dl }
}

/// Where DG1's hash sits in an LDS security object.
pub struct Lds {
    /// DER length of the whole object (header included).
    pub len: u32,
    /// Offset of DG1's hash value.
    pub dg1_hash_at: u32,
}

/// Walks an LDS security object (ICAO 9303 part 10, `LDSSecurityObject`)
/// from offset 0:
///
/// ```text
/// SEQUENCE { version INTEGER (0 | 1),
///            hashAlgorithm SEQUENCE { OID, NULL OPTIONAL },
///            dataGroupHashValues SEQUENCE OF SEQUENCE { INTEGER (1..16), OCTET STRING },
///            ldsVersionInfo SEQUENCE OPTIONAL }   -- present exactly when version = 1
/// ```
///
/// The hash algorithm OID (whole TLV) must be `hash_oid` and every hash `D`
/// bytes. At most `MAX_DATA_GROUPS` entries; DG1 appears exactly once, at
/// `dg1_offset`. Other data groups are walked but not interpreted.
pub fn parse_lds<let N: u32, let O: u32, let D: u32>(
    lds: [u8; N],
    hash_oid: [u8; O],
    dg1_offset: u32,
) -> Lds {
    let outer = expect(lds, 0, N, TAG_SEQUENCE);
    let len = outer.end(0);
    let version_at = outer.header_len;
    assert_bytes(lds, version_at, [TAG_INTEGER, 0x01]);
    let version = lds[version_at + 2];
    assert(version <= 1, "LDS security object version must be 0 or 1");

    let alg_at = version_at + 3;
    let alg = expect(lds, alg_at, len, TAG_SEQUENCE);
    assert_bytes(lds, alg_at + alg.header_len, hash_oid);
    let params = alg.len - O;
    assert((params == 0) | (params == 2), "hash parameters must be absent or NULL");
    if params == 2 {
        assert_bytes(lds, alg_at + alg.header_len + O, [0x05, 0x00]);
    }

    let list_at = alg.end(alg_at);
    let list = expect(lds, list_at, len, TAG_SEQUENCE);
    let list_end = list.end(list_at);
    let mut o = list_at + list.header_len;
    let mut dg1_count = 0;
    let mut dg1_found = false;
    for _ in 0..MAX_DATA_GROUPS {
        if o < list_end {
            // SEQUENCE { INTEGER n, OCTET STRING hash }: short lengths only (D ≤ 64).
            assert_bytes(lds, o, [TAG_SEQUENCE, (5 + D) as u8, TAG_INTEGER, 0x01]);
            let n = lds[o + 4];
            assert((n >= 1) & (n <= 16), "data group number out of range");
            assert_bytes(lds, o + 5, [TAG_OCTET_STRING, D as u8]);
            dg1_count += (n == 1) as u32;
            dg1_found |= (o == dg1_offset) & (n == 1);
            o += 7 + D;
        }
    }
    assert_eq(o, list_end, "LDS security object lists more data groups than supported");
    assert_eq(dg1_count, 1, "DG1 must be listed exactly once");
    assert(dg1_found, "dg1_offset is not DG1's entry");

    if version == 1 {
        let info = expect(lds, list_end, len, TAG_SEQUENCE);
        assert_eq(info.end(list_end), len, "trailing bytes after ldsVersionInfo");
    } else {
        assert_eq(list_end, len, "trailing bytes after dataGroupHashValues");
    }
    Lds { len, dg1_hash_at: dg1_offset + 7 }
}

/// Asserts every byte at or past `len` is zero, so a fixed-size buffer has one
/// representation per value (commitments hash the whole buffer).
pub fn assert_zero_padded<let N: u32>(buf: [u8; N], len: u32) {
    for i in 0..N {
        if i >= len {
            assert_eq(buf[i], 0, "bytes past the DER length must be zero");
        }
    }
}
