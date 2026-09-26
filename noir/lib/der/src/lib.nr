//! Constrained DER reading for X.509 TBSCertificates (and, later, CMS
//! structures). Every value read here is constrained against the buffer: a
//! prover cannot point a field at bytes that do not encode it.
//! Specification and review notes: README.md.

mod tests;
mod vectors;

/// Tags used by the certificate walk.
pub global TAG_SEQUENCE: u8 = 0x30;
pub global TAG_INTEGER: u8 = 0x02;
pub global TAG_UTC_TIME: u8 = 0x17;
pub global TAG_GENERALIZED_TIME: u8 = 0x18;
pub global TAG_CONTEXT_0: u8 = 0xa0;

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

/// Asserts every byte at or past `len` is zero, so a fixed-size buffer has one
/// representation per value (commitments hash the whole buffer).
pub fn assert_zero_padded<let N: u32>(buf: [u8; N], len: u32) {
    for i in 0..N {
        if i >= len {
            assert_eq(buf[i], 0, "bytes past the DER length must be zero");
        }
    }
}
