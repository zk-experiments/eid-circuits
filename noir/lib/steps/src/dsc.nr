//! Step A (DSC): the CSCA that signed the DSC certificate is registered, was
//! valid when the DSC was issued (ICAO chain model), and has not revoked it.
//!
//! The binary for each signature group does, in this order:
//! 1. `let f = dsc::check(...)`, which parses the TBSCertificate and runs the
//!    registry and revocation checks (below);
//! 2. hashes `tbs[..f.len]` with its hash and verifies the CSCA signature with
//!    the same `csca_key` bytes (and, for RSA, `header.exponent`);
//! 3. returns `[dsc::commitment(...), hash_id]` as public outputs.

use csca_registry::{
    Exclusion, hash, KEY_TREE_HEIGHT, KeyHeader, MerklePath, pack_be, REVOCATION_TREE_HEIGHT,
    verify_key, verify_not_revoked,
};
use eid_der::{assert_zero_padded, parse_tbs, TbsFields};

/// Everything the DSC step proves about besides the signature.
pub struct Witness<let T: u32, let K: u32> {
    /// DSC TBSCertificate, zero-padded to the bucket size `T`.
    pub tbs: [u8; T],
    /// CSCA key material committed in the registry leaf: RSA modulus, or EC `x ‖ y`.
    pub csca_key: [u8; K],
    /// CSCA leaf header (country, key type, curve, size, exponent, period).
    pub header: KeyHeader,
    /// Path of the CSCA leaf in the key tree.
    pub key_path: MerklePath<KEY_TREE_HEIGHT>,
    /// Revocation tree root (bound by the registry root).
    pub revocations_root: Field,
    /// Proof that the DSC serial is not revoked under the CSCA key.
    pub not_revoked: Exclusion<REVOCATION_TREE_HEIGHT>,
}

/// What this circuit variant verifies with: the leaf header must say the same.
pub struct KeyKind {
    /// `csca_registry::KEY_TYPE_RSA` or `KEY_TYPE_EC`.
    pub key_type: u8,
    /// Curve id (0 for RSA).
    pub curve: u8,
    /// Key size in bits.
    pub bits: u16,
}

/// Parses the DSC TBSCertificate and checks it against the registry:
/// - the buffer is the DER TBSCertificate followed only by zeros;
/// - the CSCA leaf header matches `kind`, the variant's key type and size;
/// - the CSCA key is a leaf under `root` whose period covers the DSC's
///   `notBefore` (chain model);
/// - the DSC serial is not in the revocation tree under that key.
///
/// Returns the parsed fields; the caller verifies the signature over
/// `tbs[..len]` with `w.csca_key`.
pub fn check<let T: u32, let K: u32, let M: u32>(
    root: Field,
    w: Witness<T, K>,
    kind: KeyKind,
) -> TbsFields {
    let f = parse_tbs(w.tbs);
    assert_zero_padded(w.tbs, f.len);
    assert_eq(w.header.key_type, kind.key_type, "CSCA key type does not match the circuit");
    assert_eq(w.header.curve, kind.curve, "CSCA curve does not match the circuit");
    assert_eq(w.header.bits, kind.bits, "CSCA key size does not match the circuit");
    let key_hash = verify_key::<K, M>(
        root,
        w.revocations_root,
        w.header,
        w.csca_key,
        w.key_path,
        f.not_before,
    );
    verify_not_revoked(w.revocations_root, key_hash, f.serial, w.not_revoked);
    f
}

/// Commitment passed to the SOD step:
/// `H(salt, country, hash_id, len, pack_be(tbs))`, with the country's three
/// ICAO letters and the whole zero-padded bucket. The SOD step recomputes it
/// from the same TBSCertificate to read the DSC key.
pub fn commitment<let T: u32>(
    salt: Field,
    country: [u8; 3],
    hash_id: u8,
    tbs: [u8; T],
    len: u32,
) -> Field {
    let packed: [Field; (T + 30) / 31] = pack_be(tbs);
    let mut inputs: [Field; 4 + (T + 30) / 31] = [0; 4 + (T + 30) / 31];
    inputs[0] = salt;
    inputs[1] = crate::country_field(country);
    inputs[2] = hash_id as Field;
    inputs[3] = len as Field;
    for i in 0..(T + 30) / 31 {
        inputs[4 + i] = packed[i];
    }
    hash(inputs)
}
