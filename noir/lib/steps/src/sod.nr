//! Step B (SOD): the DSC that step A proved signed the document's security
//! object, and the signed attributes carry that object's digest.
//!
//! The binary for each signature group does, in this order:
//! 1. `let (f, a) = sod::parse(tbs, attrs, md_offset)`, which walks the DSC
//!    TBSCertificate and the signed attributes (below);
//! 2. reads the DSC key from `tbs` at `f.spki_offset` with
//!    `eid_der::spki_rsa` or `eid_der::spki_ec`, which also check the key's
//!    algorithm (and curve);
//! 3. hashes `attrs[..a.len]` with its hash and verifies the DSC signature;
//! 4. returns `[dsc::commitment(...), sod::commitment(...)]`: the first must
//!    equal step A's output, the second is passed to step C.

use csca_registry::{hash, pack_be};
use eid_der::{assert_zero_padded, parse_signed_attrs, parse_tbs, SignedAttrs, TbsFields};

/// Bucket size for the signed attributes (eMRTDs use about 100 to 200 bytes).
pub global ATTRS_BUCKET: u32 = 256;

/// Parses the DSC TBSCertificate and the SignerInfo's signed attributes:
/// - `tbs` is a DER TBSCertificate followed only by zeros;
/// - `attrs` is the signed attributes in signed form (a DER SET), followed
///   only by zeros, and `md_offset` is its messageDigest attribute.
pub fn parse<let T: u32, let A: u32>(
    tbs: [u8; T],
    attrs: [u8; A],
    md_offset: u32,
) -> (TbsFields, SignedAttrs) {
    let f = parse_tbs(tbs);
    assert_zero_padded(tbs, f.len);
    let a = parse_signed_attrs(attrs, md_offset);
    assert_zero_padded(attrs, a.len);
    (f, a)
}

/// Commitment passed to the envelope step:
/// `H(salt, country, digest_len, pack_be(digest))`, with the messageDigest
/// zero-padded to 64 bytes. Step C hashes the eContent and compares.
pub fn commitment(salt: Field, country: [u8; 3], a: SignedAttrs) -> Field {
    let packed: [Field; 3] = pack_be(a.digest);
    hash([
        salt,
        crate::country_field(country),
        a.digest_len as Field,
        packed[0],
        packed[1],
        packed[2],
    ])
}
