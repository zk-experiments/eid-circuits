//! Picks the three step circuits a document needs and checks the document
//! natively first, so a proof is only attempted when it can succeed.
//!
//! Everything comes from the NFC read (EF.SOD, DG1) and the published
//! registry:
//! - **DSC step:** the CSCA key (found by verifying the DSC certificate against
//!   the registry's keys) and the DSC certificate's signature scheme;
//! - **SOD step:** the DSC's key and the SignerInfo signature scheme;
//! - **document step:** the SignerInfo digest algorithm and the LDS security
//!   object's data group hash;
//! - buckets from the TBSCertificate and eContent lengths.

use crate::config::{bucket, document_package, lds_bucket, Config, LDS_HASHES};
use crate::mrz::{parse_dg1, registry_country};
use crate::sod::Sod;
use anyhow::{bail, ensure, Context, Result};
use csca_registry::commands::prove::{prove_key, prove_not_revoked};
use csca_registry::crypto::{self, Curve, PublicKey};
use csca_registry::output::{Key, Registry};

/// The circuits a document needs, with what they were chosen from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    /// ICAO code of the CSCA's registry leaf (also the MRZ issuing state).
    pub country: String,
    /// Registry id of the CSCA key.
    pub csca_key: String,
    /// Step circuits (Noir package names).
    pub dsc: String,
    pub sod: String,
    pub document: String,
    /// Circuit packs holding these circuits: `common` (the document steps),
    /// the CSCA key's family (DSC step) and the DSC key's (SOD step). Fetch
    /// these rather than single circuits, so the host learns only key
    /// families.
    pub packs: Vec<String>,
}

/// OID of a registry curve id (the curves the circuits support).
fn curve_oid(id: u8) -> Option<&'static str> {
    Some(match id {
        3 => "1.2.840.10045.3.1.7",
        4 => "1.3.132.0.34",
        5 => "1.3.132.0.35",
        12 => "1.3.36.3.3.2.8.1.1.7",
        16 => "1.3.36.3.3.2.8.1.1.11",
        18 => "1.3.36.3.3.2.8.1.1.13",
        _ => return None,
    })
}

/// A registry key as a verifiable public key.
pub fn public_key(k: &Key) -> Option<PublicKey> {
    let material = hex::decode(k.public_key.trim_start_matches("0x")).ok()?;
    match k.key_type {
        1 => {
            let e = k.exponent.to_be_bytes();
            let first = e.iter().position(|b| *b != 0).unwrap_or(3);
            Some(PublicKey::Rsa {
                n: material,
                e: e[first..].to_vec(),
            })
        }
        2 => Some(PublicKey::Ec {
            curve: Curve::from_oid(curve_oid(k.curve)?),
            point: [vec![0x04], material].concat(),
        }),
        _ => None,
    }
}

fn label(scheme: &crypto::Scheme, key: &PublicKey) -> String {
    let key = match key {
        PublicKey::Rsa { .. } => format!("RSA-{}", key.bits()),
        PublicKey::Ec { curve: Some(c), .. } => c.name().to_string(),
        PublicKey::Ec { curve: None, .. } => "an unknown curve".to_string(),
    };
    format!("{} with {key}", scheme.name())
}

/// Selects the step circuits for a document and checks, natively, every
/// statement the proofs will make at date `at` (unix seconds).
pub fn select(reg: &Registry, ef_sod: &[u8], dg1: &[u8], at: i64) -> Result<Selection> {
    let sod = Sod::parse(ef_sod)?;
    let dsc = &sod.dsc;
    let dsc_scheme = dsc
        .scheme
        .clone()
        .map_err(|e| anyhow::anyhow!("DSC signature: {e}"))?;

    // The CSCA: a registry key that verifies the DSC certificate. Keys of the
    // DSC's country first, then all of them.
    let (same, other): (Vec<&Key>, Vec<&Key>) =
        reg.keys.iter().partition(|k| k.country == dsc.country);
    let (csca, csca_key) = same
        .into_iter()
        .chain(other)
        .find_map(|k| {
            let pk = public_key(k)?;
            dsc.verify_with(&pk).is_ok().then_some((k, pk))
        })
        .context("no CSCA in the registry verifies this DSC certificate")?;
    prove_key(reg, &csca.id, dsc.not_before)
        .context("the CSCA was not valid when the DSC was issued")?;
    prove_not_revoked(reg, &csca.id, &hex::encode(&dsc.serial))?;
    let a = Config::from_scheme(&dsc_scheme, &csca_key)
        .with_context(|| format!("no DSC step circuit for {}", label(&dsc_scheme, &csca_key)))?;
    let tbs_len = csca_registry::der::signed_parts(&dsc.der)
        .context("malformed DSC certificate")?
        .0
        .len();
    let t = bucket(tbs_len)
        .with_context(|| format!("DSC TBSCertificate of {tbs_len} bytes exceeds every bucket"))?;

    // The DSC signed the SOD.
    let dsc_key = dsc
        .key
        .clone()
        .map_err(|e| anyhow::anyhow!("DSC key: {e}"))?;
    crypto::verify(&sod.scheme, &dsc_key, &sod.signed_attrs, &sod.signature)
        .map_err(|e| anyhow::anyhow!("the DSC's SOD signature does not verify: {e}"))?;
    let b = Config::from_scheme(&sod.scheme, &dsc_key)
        .with_context(|| format!("no SOD step circuit for {}", label(&sod.scheme, &dsc_key)))?;

    // The SOD covers the eContent, which lists this DG1.
    ensure!(
        sod.digest.digest(&sod.econtent) == sod.message_digest,
        "messageDigest does not match the eContent"
    );
    let (dg_hash, listed) = sod.data_group_hash(1)?;
    ensure!(
        dg_hash.digest(dg1) == listed,
        "DG1 does not match the hash the SOD lists"
    );
    for h in [sod.digest, dg_hash] {
        ensure!(
            LDS_HASHES.contains(&h),
            "no document circuit for {}",
            h.name()
        );
    }
    let e = lds_bucket(sod.econtent.len()).with_context(|| {
        format!(
            "eContent of {} bytes exceeds every bucket",
            sod.econtent.len()
        )
    })?;

    // DG1: issuing state and expiry.
    let mrz = parse_dg1(dg1)?;
    let country = registry_country(&mrz.issuing_state);
    ensure!(
        country == csca.country_code,
        "issuing state {} does not match the CSCA's country {}",
        mrz.issuing_state,
        csca.country_code
    );
    if at > mrz.expires {
        bail!("the document expired before the given date");
    }

    Ok(Selection {
        country,
        csca_key: csca.id.clone(),
        dsc: a.step_package("dsc", t),
        sod: b.step_package("sod", t),
        document: document_package(sod.digest, dg_hash, e),
        packs: {
            let mut p = vec!["common".to_string(), a.family(), b.family()];
            p.dedup();
            p
        },
    })
}
