//! `rust/eid-prover/tests/data/documents.json`: complete synthetic documents
//! (a mock CSCA, the EF.SOD with its DSC, DG1) and the circuits each needs,
//! derived from how the document was built, for the prover's selection tests.

use crate::circuits::SAMPLE_DATE;
use crate::mock::{Csca, Doc, Lds};
use anyhow::{ensure, Context, Result};
use csca_registry::cert::Cert;
use csca_registry::crypto::Hash;
use eid_prover::config::{bucket, envelope_package, lds_bucket, Config};

/// (name, CSCA config, DSC config, eContent hash, data group hash, LDS v1, DG11 listed)
const CASES: &[(&str, Config, Config, Hash, Hash, bool, bool)] = &[
    (
        "rsa4096_csca_p256_dsc",
        Config::Pkcs1 {
            bits: 4096,
            hash: Hash::Sha256,
        },
        Config::Ecdsa {
            curve: "p256",
            hash: Hash::Sha256,
        },
        Hash::Sha256,
        Hash::Sha256,
        false,
        true,
    ),
    (
        "bp512_csca_bp256_dsc",
        Config::Ecdsa {
            curve: "bp512",
            hash: Hash::Sha512,
        },
        Config::Ecdsa {
            curve: "bp256",
            hash: Hash::Sha256,
        },
        Hash::Sha256,
        Hash::Sha512,
        true,
        false,
    ),
    (
        "pss_csca_rsa2048_dsc",
        Config::Pss {
            bits: 4096,
            hash: Hash::Sha256,
            salt: 32,
        },
        Config::Pkcs1 {
            bits: 2048,
            hash: Hash::Sha1,
        },
        Hash::Sha1,
        Hash::Sha1,
        false,
        false,
    ),
    (
        "p521_csca_pss_dsc",
        Config::Ecdsa {
            curve: "p521",
            hash: Hash::Sha512,
        },
        Config::Pss {
            bits: 3072,
            hash: Hash::Sha384,
            salt: 48,
        },
        Hash::Sha384,
        Hash::Sha384,
        true,
        true,
    ),
];

pub(crate) fn documents() -> Result<String> {
    let mut cases = vec![];
    for &(name, csca_config, dsc_config, md, dg, v1, with_dg11) in CASES {
        let csca = Csca::new(csca_config, "DE")?;
        let lds = Lds {
            md_hash: md,
            dg_hash: dg,
            v1,
            with_dg11,
        };
        let doc = Doc::issued(
            &csca,
            dsc_config,
            lds,
            "D<<",
            crate::circuits::SAMPLE_EXPIRY,
        )?;
        // The DSC certificate must verify under the CSCA, as a real one would.
        let dsc = Cert::from_der(&doc.dsc_cert)?;
        let csca_cert = Cert::from_der(&csca.cert)?;
        let csca_key = csca_cert.key.clone().map_err(|e| anyhow::anyhow!("{e}"))?;
        dsc.verify_with(&csca_key)
            .map_err(|e| anyhow::anyhow!("{name}: DSC: {e}"))?;
        csca_cert
            .verify_with(&csca_key)
            .map_err(|e| anyhow::anyhow!("{name}: CSCA: {e}"))?;
        let t = bucket(doc.tbs.len()).context("TBS fits no bucket")?;
        let e = lds_bucket(doc.econtent.len()).context("eContent fits no bucket")?;
        ensure!(
            Config::of(&dsc, &csca_key) == Some(csca_config),
            "{name}: CSCA config"
        );
        cases.push(serde_json::json!({
            "name": name,
            "csca": hex::encode(&csca.cert),
            "ef_sod": hex::encode(&doc.ef_sod),
            "dg1": hex::encode(&doc.dg1),
            "date": SAMPLE_DATE,
            "expect": {
                "country": "DEU",
                "dsc": csca_config.step_package("dsc", t),
                "sod": dsc_config.step_package("sod", t),
                "envelope": envelope_package(md, dg, e),
            },
        }));
    }
    let mut out = serde_json::to_string_pretty(&serde_json::json!({
        "generated_by": "eid-vectors documents (rust/eid-vectors/src/documents.rs); do not edit",
        "documents": cases,
    }))?;
    out.push('\n');
    Ok(out)
}
