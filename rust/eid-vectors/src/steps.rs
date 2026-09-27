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

/// SOD step cases: (vector name, configuration). They cover rsaEncryption
/// and id-RSASSA-PSS keys, a named curve (P-256) and explicit parameters
/// (brainpoolP256r1, P-521 with 66-byte coordinates).
const SOD_CASES: &[(&str, crate::circuits::Config)] = &[
    (
        "pkcs1_2048",
        crate::circuits::Config::Pkcs1 {
            bits: 2048,
            hash: csca_registry::crypto::Hash::Sha256,
        },
    ),
    (
        "pss_3072",
        crate::circuits::Config::Pss {
            bits: 3072,
            hash: csca_registry::crypto::Hash::Sha256,
            salt: 32,
        },
    ),
    (
        "p256",
        crate::circuits::Config::Ecdsa {
            curve: "p256",
            hash: csca_registry::crypto::Hash::Sha256,
        },
    ),
    (
        "bp256",
        crate::circuits::Config::Ecdsa {
            curve: "bp256",
            hash: csca_registry::crypto::Hash::Sha256,
        },
    ),
    (
        "p521",
        crate::circuits::Config::Ecdsa {
            curve: "p521",
            hash: csca_registry::crypto::Hash::Sha512,
        },
    ),
];

/// `noir/lib/steps/src/sod_vectors.nr`: `sod::parse` and the DSC key read
/// for synthetic documents (rust/eid-vectors/src/mock.rs).
pub(crate) fn sod_vectors() -> Result<String> {
    use csca_registry::crypto::PublicKey;
    let mut out = String::from(
        "// Generated by `eid-vectors steps` from synthetic documents (rust/eid-vectors/src/mock.rs). Do not edit.\n\n\
         use crate::sod::parse;\n\
         use eid_der::{curves, spki_ec, spki_rsa};\n\n",
    );
    for (name, config) in SOD_CASES {
        let doc = crate::mock::Doc::new(*config, "UTO", "340415")?;
        let t = bucket(doc.tbs.len()).context("mock TBS fits no bucket")?;
        let mut tbs = doc.tbs.clone();
        tbs.resize(t, 0);
        let mut attrs = doc.attrs.clone();
        attrs.resize(256, 0);
        let md = doc.lds_hash.digest(&doc.econtent);
        let mut digest = md.clone();
        digest.resize(64, 0);
        let up = name.to_uppercase();
        writeln!(
            out,
            "pub(crate) global {up}_TBS: [u8; {t}] = {};\npub(crate) global {up}_ATTRS: [u8; 256] = {};\npub(crate) global {up}_MD_OFFSET: u32 = {};\n",
            bytes(&tbs),
            bytes(&attrs),
            doc.md_offset
        )?;
        let key = match &doc.dsc_key {
            PublicKey::Rsa { n, e } => {
                let exponent = e.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
                format!(
                    "    let (n, e) = spki_rsa::<{t}, {}>({up}_TBS, f.spki_offset, f.len);\n    assert_eq(n, {});\n    assert_eq(e, {exponent});",
                    n.len(),
                    bytes(n)
                )
            }
            PublicKey::Ec {
                curve: Some(c),
                point,
            } => {
                let (x, y) = point
                    .get(1..)
                    .context("point")?
                    .split_at((point.len() - 1) / 2);
                format!(
                    "    let (x, y) = spki_ec({up}_TBS, f.spki_offset, f.len, curves::{});\n    assert_eq(x, {});\n    assert_eq(y, {});",
                    crate::curves::der_global(c.name())?,
                    bytes(x),
                    bytes(y)
                )
            }
            PublicKey::Ec { curve: None, .. } => bail!("{name}: unknown curve"),
        };
        writeln!(
            out,
            "#[test]\nfn sod_{name}() {{\n    let (f, a) = parse({up}_TBS, {up}_ATTRS, {up}_MD_OFFSET);\n    assert_eq(f.len, {});\n    assert_eq(a.len, {});\n    assert_eq(a.digest_len, {});\n    assert_eq(a.digest, {});\n{key}\n}}\n",
            doc.tbs.len(),
            doc.attrs.len(),
            md.len(),
            bytes(&digest)
        )?;
    }
    Ok(out)
}
