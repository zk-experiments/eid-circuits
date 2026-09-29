//! Circuit inputs for the three steps, as `Prover.toml` text (`nargo execute`
//! reads it; `eid-vectors` writes the samples with the same functions).
//!
//! The step functions take the pieces a step needs, so samples built from
//! fixtures and documents read over NFC go through the same code;
//! [`witnesses`] runs them on a whole document.

use crate::config::bucket;
use crate::select::{select, Selection};
use crate::sod::Sod;
use anyhow::{bail, ensure, Context, Result};
use csca_registry::cert::Cert;
use csca_registry::commands::prove::{prove_key, prove_not_revoked};
use csca_registry::crypto::{Hash, PublicKey};
use csca_registry::der;
use csca_registry::output::Registry;
use std::fmt::Write as _;

/// Signed-attributes bucket of the SOD step.
pub const ATTRS_BUCKET: usize = 256;
/// DG1 buffer of the envelope step.
pub const DG1_MAX: usize = 95;

/// A signature in circuit form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signature {
    /// Big-endian, left-padded to the modulus size.
    Rsa(Vec<u8>),
    /// `r` and `s`, each left-padded to the coordinate size.
    Ecdsa { r: Vec<u8>, s: Vec<u8> },
}

impl Signature {
    /// From the encoding certificates and SignerInfos use: raw for RSA, DER
    /// `SEQUENCE { r, s }` for ECDSA.
    pub fn from_der(key: &PublicKey, sig: &[u8]) -> Result<Self> {
        match key {
            PublicKey::Rsa { n, .. } => {
                ensure!(
                    sig.len() <= n.len(),
                    "RSA signature longer than the modulus"
                );
                Ok(Self::Rsa(left_pad(sig, n.len())))
            }
            PublicKey::Ec { point, .. } => {
                let sz = (point.len() - 1) / 2;
                let (seq, _) = der::expect(sig, 0x30).context("ECDSA signature")?;
                let parts = der::children(seq.content).context("ECDSA signature")?;
                let [r, s] = parts.as_slice() else {
                    bail!("ECDSA signature is not (r, s)")
                };
                let fit = |v: &[u8]| -> Result<Vec<u8>> {
                    let v = der::uint(v);
                    ensure!(v.len() <= sz, "ECDSA signature value too long");
                    Ok(left_pad(v, sz))
                };
                Ok(Self::Ecdsa {
                    r: fit(r.content)?,
                    s: fit(s.content)?,
                })
            }
        }
    }
}

fn left_pad(v: &[u8], n: usize) -> Vec<u8> {
    let mut o = vec![0u8; n - v.len()];
    o.extend_from_slice(v);
    o
}

fn padded(v: &[u8], n: usize) -> Result<Vec<u8>> {
    ensure!(
        v.len() <= n,
        "{} bytes do not fit a {n}-byte buffer",
        v.len()
    );
    let mut o = v.to_vec();
    o.resize(n, 0);
    Ok(o)
}

/// A TOML byte array.
pub fn bytes(b: &[u8]) -> String {
    let body: Vec<String> = b.iter().map(u8::to_string).collect();
    format!("[{}]", body.join(", "))
}

fn quoted(v: &[String]) -> String {
    format!(
        "[{}]",
        v.iter()
            .map(|s| format!("\"{s}\""))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// The id `dsc::commitment` commits to for a hash (`eid_steps::HASH_*`).
pub fn hash_id(h: Hash) -> u8 {
    match h {
        Hash::Sha1 => 1,
        Hash::Sha224 => 2,
        Hash::Sha256 => 3,
        Hash::Sha384 => 4,
        Hash::Sha512 => 5,
    }
}

/// `redc` and `signature` (RSA) or `r` and `s` (ECDSA) lines.
fn signature_toml(key: &PublicKey, sig: &Signature) -> Result<String> {
    Ok(match (key, sig) {
        (PublicKey::Rsa { n, .. }, Signature::Rsa(s)) => {
            // Barrett parameter floor(2^(2·bits + 6) / n) in 120-bit limbs.
            let n = num_bigint::BigUint::from_bytes_be(n);
            let bits = usize::try_from(n.bits())?;
            let redc = (num_bigint::BigUint::from(1u8) << (2 * bits + 6)) / &n;
            let mask = (num_bigint::BigUint::from(1u8) << 120u32) - 1u8;
            let limbs: Vec<String> = (0..bits.div_ceil(120))
                .map(|i| format!("\"0x{:x}\"", (&redc >> (120 * i)) & &mask))
                .collect();
            format!("redc = [{}]\nsignature = {}\n", limbs.join(", "), bytes(s))
        }
        (PublicKey::Ec { .. }, Signature::Ecdsa { r, s }) => {
            format!("r = {}\ns = {}\n", bytes(r), bytes(s))
        }
        _ => bail!("signature does not match the key type"),
    })
}

/// DSC step inputs: the CSCA leaf `csca_key` (registry id) signed `dsc`.
pub fn dsc_toml(reg: &Registry, csca_key: &str, dsc: &Cert, salt: &str) -> Result<String> {
    let key = reg
        .keys
        .iter()
        .find(|k| k.id == csca_key)
        .context("CSCA key not in the registry")?;
    let (tbs, _, _, sig) = der::signed_parts(&dsc.der).context("malformed DSC certificate")?;
    let t = bucket(tbs.len()).context("TBSCertificate fits no bucket")?;
    let kp = prove_key(reg, csca_key, dsc.not_before)?;
    let nr = prove_not_revoked(reg, csca_key, &hex::encode(&dsc.serial))?;
    let material = hex::decode(key.public_key.trim_start_matches("0x"))?;
    let pk = crate::select::public_key(key).context("unsupported CSCA key")?;
    let mut out = format!("root = \"{}\"\nsalt = \"{salt}\"\n", reg.commitment.root);
    out.push_str(&signature_toml(&pk, &Signature::from_der(&pk, sig)?)?);
    let path =
        |idx: &str, sib: &[String]| format!("index = \"{idx}\"\nsiblings = {}\n", quoted(sib));
    let lower = nr.lower.as_ref();
    let zero_path = vec!["0".to_string(); nr.upper.siblings.len()];
    write!(
        out,
        "\n[w]\ntbs = {}\ncsca_key = {}\nrevocations_root = \"{}\"\n\n[w.header]\ncountry = {}\nkey_type = {}\ncurve = {}\nbits = {}\nexponent = {}\nopen = \"{}\"\nclose = \"{}\"\n\n[w.key_path]\n{}\n[w.not_revoked]\nhas_lower = {}\nlower_leaf = \"{}\"\nupper_leaf = \"{}\"\n\n[w.not_revoked.lower]\n{}\n[w.not_revoked.upper]\n{}",
        bytes(&padded(tbs, t)?),
        bytes(&material),
        kp.revocations_root,
        bytes(kp.country_code.as_bytes()),
        kp.key_type,
        kp.curve,
        kp.bits,
        kp.exponent,
        kp.open,
        kp.close,
        path(&kp.proof.index.to_string(), &kp.proof.siblings),
        lower.is_some(),
        lower.map_or("0".into(), |l| l.leaf.clone()),
        nr.upper.leaf,
        path(&lower.map_or("0".into(), |l| l.index.to_string()), lower.map_or(&zero_path, |l| &l.siblings)),
        path(&nr.upper.index.to_string(), &nr.upper.siblings),
    )?;
    Ok(out)
}

/// SOD step inputs. `dsc_salt`, `dsc_hash_id` and `country` must be the
/// DSC step's, so the recomputed commitment matches.
#[allow(clippy::too_many_arguments)]
pub fn sod_toml(
    tbs: &[u8],
    attrs: &[u8],
    md_offset: usize,
    dsc_key: &PublicKey,
    sig: &Signature,
    dsc_salt: &str,
    dsc_hash_id: u8,
    country: &str,
    salt: &str,
) -> Result<String> {
    let t = bucket(tbs.len()).context("TBSCertificate fits no bucket")?;
    let mut out = format!(
        "dsc_salt = \"{dsc_salt}\"\ndsc_hash_id = {dsc_hash_id}\ncountry = {}\nsalt = \"{salt}\"\ntbs = {}\nattrs = {}\nmd_offset = {md_offset}\n",
        bytes(country.as_bytes()),
        bytes(&padded(tbs, t)?),
        bytes(&padded(attrs, ATTRS_BUCKET)?),
    );
    out.push_str(&signature_toml(dsc_key, sig)?);
    Ok(out)
}

/// Document step inputs (everything but the eContent bucket comes from the document).
pub struct Document<'a> {
    pub econtent: &'a [u8],
    pub bucket: usize,
    pub digest: &'a [u8],
    pub dg1: &'a [u8],
    pub dg1_offset: usize,
    pub sod_salt: &'a str,
    pub country: &'a str,
    pub date: i64,
    pub scope: &'a str,
    /// The salt of DG1's payload commitment (the link an envelope app opens).
    pub dg1_salt: &'a str,
}

/// Document step inputs.
pub fn document_toml(d: &Document<'_>) -> Result<String> {
    Ok(format!(
        "date = {}\nscope = \"{}\"\ndg1_salt = \"{}\"\n\n[w]\nsod_salt = \"{}\"\ncountry = {}\ndigest = {}\ndigest_len = {}\necontent = {}\ndg1_offset = {}\ndg1 = {}\n",
        d.date,
        d.scope,
        d.dg1_salt,
        d.sod_salt,
        bytes(d.country.as_bytes()),
        bytes(&padded(d.digest, 64)?),
        d.digest.len(),
        bytes(&padded(d.econtent, d.bucket)?),
        d.dg1_offset,
        bytes(&padded(d.dg1, DG1_MAX)?),
    ))
}

/// The salts and the proof's public values. The three salts must be fresh
/// and uniformly random per proof (decimal strings): `dsc_salt` and
/// `sod_salt` hide the links between the steps, `dg1_salt` hides DG1's
/// payload commitment (an envelope app of the pipeline opens it with the
/// same salt).
pub struct Params {
    pub dsc_salt: String,
    pub sod_salt: String,
    pub dg1_salt: String,
    pub date: i64,
    /// Nullifier scope: "0" for none (no Sybil check, nothing linkable).
    pub scope: String,
}

/// The circuits a document needs and their inputs.
pub struct Witnesses {
    pub selection: Selection,
    pub dsc: String,
    pub sod: String,
    pub document: String,
}

/// Selects the circuits for a document (checking it natively) and builds
/// their inputs.
pub fn witnesses(reg: &Registry, ef_sod: &[u8], dg1: &[u8], p: &Params) -> Result<Witnesses> {
    let selection = select(reg, ef_sod, dg1, p.date)?;
    let sod = Sod::parse(ef_sod)?;
    let dsc_hash = sod.dsc.scheme.clone().map_err(|e| anyhow::anyhow!("{e}"))?;
    let dsc_hash_id = hash_id(crate::config::scheme_hash(&dsc_hash));
    let (tbs, ..) = der::signed_parts(&sod.dsc.der).context("malformed DSC certificate")?;
    let dsc_key = sod
        .dsc
        .key
        .clone()
        .map_err(|e| anyhow::anyhow!("DSC key: {e}"))?;
    let dg1_offset = sod.data_group_entry_offset(1)?;
    let bucket =
        crate::config::lds_bucket(sod.econtent.len()).context("eContent fits no bucket")?;
    Ok(Witnesses {
        dsc: dsc_toml(reg, &selection.csca_key, &sod.dsc, &p.dsc_salt)?,
        sod: sod_toml(
            tbs,
            &sod.signed_attrs,
            sod.md_offset,
            &dsc_key,
            &Signature::from_der(&dsc_key, &sod.signature)?,
            &p.dsc_salt,
            dsc_hash_id,
            &selection.country,
            &p.sod_salt,
        )?,
        document: document_toml(&Document {
            econtent: &sod.econtent,
            bucket,
            digest: &sod.message_digest,
            dg1,
            dg1_offset,
            sod_salt: &p.sod_salt,
            country: &selection.country,
            date: p.date,
            scope: &p.scope,
            dg1_salt: &p.dg1_salt,
        })?,
        selection,
    })
}
