//! Vectors for `noir/lib/steps` (DSC step checks without the signature).
//!
//! The registry is built from `fixtures/sources` with csca-registry's own
//! builder, and every witness comes from its `prove key` / `prove
//! not-revoked`, exactly as a prover would obtain them. Each fixture
//! certificate stands in for a DSC: its issuer's key is the "CSCA" leaf,
//! proven at the certificate's `notBefore`.

use crate::{bytes, fixtures, ECDSA_CASES, RSA_CASES};
use anyhow::{bail, Context, Result};
use csca_registry::cert::Cert;
use csca_registry::commands::prove::{prove_key, prove_not_revoked, ProofJson};
use csca_registry::output::Registry;
use csca_registry::registry::Builder;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

/// TBSCertificate size buckets (same as zkpassport's DSC circuits).
pub(crate) const BUCKETS: [usize; 4] = [700, 1000, 1200, 1600];

pub(crate) fn registry() -> Result<Registry> {
    let mut b = Builder::default();
    b.add_path(&fixtures().join("sources"))?;
    b.finish()
}

pub(crate) fn bucket(len: usize) -> Option<usize> {
    BUCKETS.into_iter().find(|b| *b >= len)
}

fn path(p: &ProofJson) -> String {
    format!(
        "MerklePath {{ index: {}, siblings: [{}] }}",
        p.index,
        p.siblings.join(", ")
    )
}

/// CSCA leaf header values.
pub(crate) struct HeaderParts {
    pub country: Vec<u8>,
    pub key_type: u8,
    pub curve: u8,
    pub bits: u16,
    pub exponent: u32,
    pub open: i64,
    pub close: i64,
}

/// The DSC step witness as plain values (rendered as Noir or TOML).
pub(crate) struct WitnessParts {
    pub tbs: Vec<u8>,
    pub csca_key: Vec<u8>,
    pub header: HeaderParts,
    pub key_index: String,
    pub key_siblings: Vec<String>,
    pub revocations_root: String,
    pub has_lower: bool,
    pub lower_leaf: String,
    pub lower_index: String,
    pub lower_siblings: Vec<String>,
    pub upper_leaf: String,
    pub upper_index: String,
    pub upper_siblings: Vec<String>,
}

/// Noir expression building `Witness` for one certificate, plus its
/// `KeyKind` and generic sizes (T, K, M).
pub(crate) struct DscCase {
    pub name: String,
    pub witness: String,
    pub witness_parts: WitnessParts,
    pub kind: String,
    pub t: usize,
    pub k: usize,
    pub len: usize,
    /// Offset of the notBefore `Time` element (tag byte) in the TBS.
    pub not_before_offset: usize,
    /// Offset of the serialNumber INTEGER (tag byte) in the TBS.
    pub serial_offset: usize,
}

pub(crate) fn dsc_case(reg: &Registry, name: &str) -> Result<DscCase> {
    let cert = Cert::from_der(&std::fs::read(fixtures().join(format!("{name}.der")))?)?;
    let issuer = Cert::from_der(&std::fs::read(
        fixtures().join(format!("{name}.issuer.der")),
    )?)?;
    let key = issuer
        .key
        .clone()
        .map_err(|e| anyhow::anyhow!("{name}: {e}"))?;
    let key_id = hex::encode(Sha256::digest(key.material()));
    let (tbs, _, _, _) = csca_registry::der::signed_parts(&cert.der).context("signed parts")?;
    let Some(t) = bucket(tbs.len()) else {
        bail!("{name}: TBS of {} bytes fits no bucket", tbs.len())
    };
    let mut padded = tbs.to_vec();
    padded.resize(t, 0);
    let kp = prove_key(reg, &key_id, cert.not_before)?;
    let nr = prove_not_revoked(reg, &key_id, &hex::encode(&cert.serial))?;
    let c = kp.country_code.as_bytes();
    let lower = nr.lower.as_ref();
    let witness_parts = WitnessParts {
        tbs: padded.clone(),
        csca_key: key.material().to_vec(),
        header: HeaderParts {
            country: c.to_vec(),
            key_type: kp.key_type,
            curve: kp.curve,
            bits: kp.bits,
            exponent: kp.exponent,
            open: kp.open,
            close: kp.close,
        },
        key_index: kp.proof.index.to_string(),
        key_siblings: kp.proof.siblings.clone(),
        revocations_root: kp.revocations_root.clone(),
        has_lower: lower.is_some(),
        lower_leaf: lower.map_or("0".into(), |l| l.leaf.clone()),
        lower_index: lower.map_or("0".into(), |l| l.index.to_string()),
        lower_siblings: lower.map_or(vec!["0".into(); 14], |l| l.siblings.clone()),
        upper_leaf: nr.upper.leaf.clone(),
        upper_index: nr.upper.index.to_string(),
        upper_siblings: nr.upper.siblings.clone(),
    };
    let witness = format!(
        "Witness {{\n        tbs: {},\n        csca_key: {},\n        header: KeyHeader {{ country: [{}, {}, {}], key_type: {}, curve: {}, bits: {}, exponent: {}, open: {}, close: {} }},\n        key_path: {},\n        revocations_root: {},\n        not_revoked: Exclusion {{\n            has_lower: {},\n            lower_leaf: {},\n            lower: {},\n            upper_leaf: {},\n            upper: {},\n        }},\n    }}",
        bytes(&padded),
        bytes(key.material()),
        c[0], c[1], c[2], kp.key_type, kp.curve, kp.bits, kp.exponent, kp.open, kp.close,
        path(&kp.proof),
        kp.revocations_root,
        lower.is_some(),
        lower.map_or("0".into(), |l| l.leaf.clone()),
        lower.map_or("MerklePath { index: 0, siblings: [0; 14] }".into(), path),
        nr.upper.leaf,
        path(&nr.upper),
    );
    // serialNumber follows `[0] version` (a0 03 02 01 02) after the outer header.
    let (outer, _) = csca_registry::der::read(tbs).context("tbs header")?;
    let serial_offset = tbs.len() - outer.content.len() + 5;
    anyhow::ensure!(
        tbs[serial_offset] == 0x02,
        "{name}: serial not where expected"
    );
    // validity.notBefore: the first UTCTime/GeneralizedTime with 13/15 bytes.
    let not_before_offset = (0..tbs.len() - 2)
        .find(|&i| (tbs[i] == 0x17 && tbs[i + 1] == 13) || (tbs[i] == 0x18 && tbs[i + 1] == 15))
        .context("no Time in TBS")?;
    let kind = format!(
        "KeyKind {{ key_type: {}, curve: {}, bits: {} }}",
        kp.key_type, kp.curve, kp.bits
    );
    Ok(DscCase {
        name: name.into(),
        witness,
        witness_parts,
        kind,
        t,
        k: key.material().len(),
        len: tbs.len(),
        not_before_offset,
        serial_offset,
    })
}

/// `noir/lib/steps/src/vectors.nr`: one `dsc::check` test per fixture certificate.
pub(crate) fn steps_vectors() -> Result<String> {
    let reg = registry()?;
    let mut out = String::from(
        "// Generated by `eid-vectors steps` from rust/eid-vectors/fixtures. Do not edit.\n\
         // Registry and proofs come from csca-registry's builder and prove commands.\n\n\
         use crate::dsc::{check, KeyKind, Witness};\n\
         use csca_registry::{Exclusion, KeyHeader, MerklePath};\n\n",
    );
    writeln!(
        out,
        "pub(crate) global ROOT: Field = {};\n",
        reg.commitment.root
    )?;
    for (name, _) in RSA_CASES.iter().chain(ECDSA_CASES) {
        let c = dsc_case(&reg, name)?;
        let m = c.k.div_ceil(31);
        writeln!(
            out,
            "pub(crate) fn {}_witness() -> Witness<{}, {}> {{\n    {}\n}}\n",
            c.name, c.t, c.k, c.witness
        )?;
        writeln!(
            out,
            "pub(crate) fn {}_kind() -> KeyKind {{\n    {}\n}}\n",
            c.name, c.kind
        )?;
        let up = c.name.to_uppercase();
        writeln!(
            out,
            "pub(crate) global {up}_NOT_BEFORE_OFFSET: u32 = {};\npub(crate) global {up}_SERIAL_OFFSET: u32 = {};\n",
            c.not_before_offset, c.serial_offset
        )?;
        writeln!(
            out,
            "#[test]\nfn {n}() {{\n    let f = check::<{t}, {k}, {m}>(ROOT, {n}_witness(), {n}_kind());\n    assert_eq(f.len, {len});\n}}\n",
            n = c.name,
            t = c.t,
            k = c.k,
            len = c.len,
        )?;
    }
    Ok(out)
}
