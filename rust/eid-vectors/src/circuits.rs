//! Generates the step circuits in `noir/circuits` and the root `Nargo.toml`.
//!
//! DSC step circuits are grouped by the CSCA's signature type
//! (`rsa_pkcs1v15`, `rsa_pss`, `ecdsa`), one per signing configuration seen in
//! the registry data (`DSC_CONFIGS`) and TBSCertificate size bucket. Each is a
//! thin binary: `eid_steps::dsc::check`, one hash, one signature check, the
//! commitment. A sample of them also gets a `Prover.toml` built from a real
//! certificate, which CI executes.

use crate::steps::registry;
use crate::{fixtures, root, ECDSA_CASES, RSA_CASES};
use anyhow::{bail, Context, Result};
use csca_registry::cert::Cert;
use csca_registry::crypto::{Hash, PublicKey};
use eid_prover::config::{
    bucket, envelope_dir, envelope_package, Config, BUCKETS, DSC_CONFIGS, LDS_BUCKETS, LDS_HASHES,
};
use eid_prover::witness;
use sha2::Digest as _;
use std::fmt::Write as _;
use std::path::PathBuf;

/// Library and bench packages, listed before the generated circuits.
const FIXED_MEMBERS: &[&str] = &[
    "noir/lib/hash",
    "noir/lib/rsa",
    "noir/lib/ecdsa",
    "noir/lib/der",
    "noir/lib/envelope",
    "noir/lib/kernel",
    "noir/lib/steps",
    "noir/kernels/dsc",
    "noir/kernels/sod",
    "noir/kernels/envelope",
    "noir/kernels/tail",
    "noir/kernels/hiding",
];

/// (curve label, csca-registry curve id, key bits, coordinate bytes, Noir wrapper)
fn curve(label: &str) -> Result<(u8, u32, usize, &'static str)> {
    Ok(match label {
        "p256" => (3, 256, 32, "verify_p256"),
        "p384" => (4, 384, 48, "verify_p384"),
        "p521" => (5, 521, 66, "verify_p521"),
        "bp256" => (12, 256, 32, "verify_bp256"),
        "bp384" => (16, 384, 48, "verify_bp384"),
        "bp512" => (18, 512, 64, "verify_bp512"),
        other => bail!("unknown curve {other}"),
    })
}

/// (name, digest bytes, `eid_hash` fn, `Digest` type, DigestInfo global, eid_steps id global)
fn hash(
    h: Hash,
) -> (
    &'static str,
    usize,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
) {
    match h {
        Hash::Sha1 => (
            "sha1",
            20,
            "sha1_var",
            "Sha1",
            "DIGEST_INFO_SHA1",
            "HASH_SHA1",
        ),
        Hash::Sha224 => (
            "sha224",
            28,
            "sha224_var",
            "Sha224",
            "DIGEST_INFO_SHA224",
            "HASH_SHA224",
        ),
        Hash::Sha256 => (
            "sha256",
            32,
            "sha256_var",
            "Sha256",
            "DIGEST_INFO_SHA256",
            "HASH_SHA256",
        ),
        Hash::Sha384 => (
            "sha384",
            48,
            "sha384_var",
            "Sha384",
            "DIGEST_INFO_SHA384",
            "HASH_SHA384",
        ),
        Hash::Sha512 => (
            "sha512",
            64,
            "sha512_var",
            "Sha512",
            "DIGEST_INFO_SHA512",
            "HASH_SHA512",
        ),
    }
}

/// `Nargo.toml` for a circuit `depth` directories below `noir/`.
fn nargo_toml(package: &str, deps: &[&str], depth: usize) -> String {
    let mut s = format!(
        "[package]\nname = \"{package}\"\ntype = \"bin\"\nauthors = [\"zk-experiments\"]\ncompiler_version = \">=1.0.0\"\n\n[dependencies]\n"
    );
    for d in deps {
        writeln!(
            s,
            "{d} = {{ path = \"{}lib/{}\" }}",
            "../".repeat(depth),
            d.trim_start_matches("eid_")
        )
        .ok();
    }
    s.push_str(
        "csca_registry = { tag = \"v0.3.1\", git = \"https://github.com/zk-experiments/csca-registry\", directory = \"noir/csca_registry\" }\n",
    );
    s
}

/// `main.nr` and `Nargo.toml` for one DSC step circuit.
fn dsc_circuit(c: Config, t: usize) -> Result<(String, String)> {
    let pkg = c.package(t);
    let (main, deps): (String, Vec<&str>) = match c {
        Config::Pkcs1 { bits, hash: h } | Config::Pss { bits, hash: h, .. } => {
            let (hn, d, hf, ht, info, id) = hash(h);
            let k = bits / 8;
            let limbs = bits.div_ceil(120);
            let m = k.div_ceil(31);
            let (title, uses, call) = match c {
                Config::Pss { salt, .. } => (
                    format!("RSASSA-PSS \u{b7} RSA-{bits} \u{b7} {} with MGF1 \u{b7} {salt}-byte salt", hn.to_uppercase()),
                    format!("use eid_hash::{{{ht}, {hf}}};\nuse eid_rsa::verify_pss;"),
                    format!(
                        "verify_pss::<{ht}, {limbs}, {bits}, 17, {d}, {salt}>(\n        w.csca_key,\n        redc,\n        w.header.exponent,\n        signature,\n        digest,\n    );"
                    ),
                ),
                _ => (
                    format!("RSASSA-PKCS1-v1_5 \u{b7} RSA-{bits} \u{b7} {}", hn.to_uppercase()),
                    format!("use eid_hash::{hf};\nuse eid_rsa::{{{info}, verify_pkcs1v15}};"),
                    format!(
                        "verify_pkcs1v15::<{limbs}, {bits}, 17, {d}, {}>(\n        w.csca_key,\n        redc,\n        w.header.exponent,\n        signature,\n        digest,\n        {info},\n    );",
                        if h == Hash::Sha1 { 15 } else { 19 }
                    ),
                ),
            };
            let main = format!(
                "//! DSC step \u{b7} {title} \u{b7} TBSCertificate \u{2264} {t} bytes.\n//!\n//! Generated by `eid-vectors circuits`; specification: docs/circuits/dsc.md.\n\n{uses}\nuse eid_steps::dsc::{{check, commitment, KeyKind, Witness}};\nuse eid_steps::{id};\n\n/// Returns `[registry root, commitment]` through the databus, to the DSC\n/// kernel that folds this proof.\nfn main(\n    root: Field,\n    salt: Field,\n    w: Witness<{t}, {k}>,\n    redc: [u128; {limbs}],\n    signature: [u8; {k}],\n) -> return_data [Field; 2] {{\n    let f = check::<{t}, {k}, {m}>(root, w, KeyKind {{ key_type: 1, curve: 0, bits: {bits} }});\n    let digest = {hf}(w.tbs, f.len);\n    {call}\n    [root, commitment(salt, w.header.country, {id}, w.tbs, f.len)]\n}}\n"
            );
            let deps = vec!["eid_hash", "eid_rsa", "eid_steps"];
            (main, deps)
        }
        Config::Ecdsa {
            curve: label,
            hash: h,
        } => {
            let (hn, d, hf, _, _, id) = hash(h);
            let (curve_id, bits, sz, wrapper) = curve(label)?;
            let k = 2 * sz;
            let m = k.div_ceil(31);
            let main = format!(
                "//! DSC step \u{b7} ECDSA \u{b7} {label} \u{b7} {} \u{b7} TBSCertificate \u{2264} {t} bytes.\n//!\n//! Generated by `eid-vectors circuits`; specification: docs/circuits/dsc.md.\n\nuse eid_ecdsa::{wrapper};\nuse eid_hash::{hf};\nuse eid_steps::dsc::{{check, commitment, KeyKind, Witness}};\nuse eid_steps::{id};\n\n/// Returns `[registry root, commitment]` through the databus, to the DSC\n/// kernel that folds this proof.\nfn main(\n    root: Field,\n    salt: Field,\n    w: Witness<{t}, {k}>,\n    r: [u8; {sz}],\n    s: [u8; {sz}],\n) -> return_data [Field; 2] {{\n    let f = check::<{t}, {k}, {m}>(root, w, KeyKind {{ key_type: 2, curve: {curve_id}, bits: {bits} }});\n    let mut x: [u8; {sz}] = [0; {sz}];\n    let mut y: [u8; {sz}] = [0; {sz}];\n    for i in 0..{sz} {{\n        x[i] = w.csca_key[i];\n        y[i] = w.csca_key[{sz} + i];\n    }}\n    {wrapper}::<{d}>(x, y, r, s, {hf}(w.tbs, f.len));\n    [root, commitment(salt, w.header.country, {id}, w.tbs, f.len)]\n}}\n",
                hn.to_uppercase()
            );
            (main, vec!["eid_ecdsa", "eid_hash", "eid_steps"])
        }
    };
    Ok((nargo_toml(&pkg, &deps, 5), main))
}

/// The signature check shared by the SOD circuits: `(uses, witness params,
/// statements)` verifying `digest` over `attrs[..a.len]` with the DSC key
/// read from `tbs`.
fn sod_verify(c: Config) -> Result<(String, String, String)> {
    Ok(match c {
        Config::Pkcs1 { bits, hash: h } | Config::Pss { bits, hash: h, .. } => {
            let (_, d, hf, ht, info, _) = hash(h);
            let k = bits / 8;
            let limbs = bits.div_ceil(120);
            let (uses, call) = match c {
                Config::Pss { salt, .. } => (
                    format!("use eid_hash::{{{ht}, {hf}}};\nuse eid_rsa::verify_pss;"),
                    format!("verify_pss::<{ht}, {limbs}, {bits}, 17, {d}, {salt}>(modulus, redc, exponent, signature, digest);"),
                ),
                _ => (
                    format!("use eid_hash::{hf};\nuse eid_rsa::{{{info}, verify_pkcs1v15}};"),
                    format!(
                        "verify_pkcs1v15::<{limbs}, {bits}, 17, {d}, {}>(\n        modulus,\n        redc,\n        exponent,\n        signature,\n        digest,\n        {info},\n    );",
                        if h == Hash::Sha1 { 15 } else { 19 }
                    ),
                ),
            };
            (
                format!("use eid_der::spki_rsa;\n{uses}"),
                format!("    redc: [u128; {limbs}],\n    signature: [u8; {k}],\n"),
                format!("let (modulus, exponent) = spki_rsa::<T, {k}>(tbs, f.spki_offset, f.len);\n    let digest = {hf}(attrs, a.len);\n    {call}"),
            )
        }
        Config::Ecdsa {
            curve: label,
            hash: h,
        } => {
            let (_, d, hf, _, _, _) = hash(h);
            let (_, _, sz, wrapper) = curve(label)?;
            (
                format!("use eid_der::{{curves::{}, spki_ec}};\nuse eid_ecdsa::{wrapper};\nuse eid_hash::{hf};", label.to_uppercase()),
                format!("    r: [u8; {sz}],\n    s: [u8; {sz}],\n"),
                format!("let (x, y) = spki_ec(tbs, f.spki_offset, f.len, {});\n    {wrapper}::<{d}>(x, y, r, s, {hf}(attrs, a.len));", label.to_uppercase()),
            )
        }
    })
}

/// `Nargo.toml` and `main.nr` for one SOD step circuit.
fn sod_circuit(c: Config, t: usize) -> Result<(String, String)> {
    let pkg = c.step_package("sod", t);
    let (uses, params, verify) = sod_verify(c)?;
    let verify = verify.replace("spki_rsa::<T,", &format!("spki_rsa::<{t},"));
    let main = format!(
        "//! SOD step \u{b7} {} \u{b7} DSC TBSCertificate \u{2264} {t} bytes.\n//!\n//! Generated by `eid-vectors circuits`; specification: docs/circuits/sod.md.\n\n{uses}\nuse eid_steps::{{dsc, sod}};\n\n/// Returns `[DSC commitment, SOD commitment]` through the databus, to the SOD\n/// kernel, which checks the first equals the DSC step's.\nfn main(\n    dsc_salt: Field,\n    dsc_hash_id: u8,\n    country: [u8; 3],\n    salt: Field,\n    tbs: [u8; {t}],\n    attrs: [u8; 256],\n    md_offset: u32,\n{params}) -> return_data [Field; 2] {{\n    let (f, a) = sod::parse(tbs, attrs, md_offset);\n    {verify}\n    [\n        dsc::commitment(dsc_salt, country, dsc_hash_id, tbs, f.len),\n        sod::commitment(salt, country, a),\n    ]\n}}\n",
        c.label()
    );
    let deps: Vec<&str> = match c {
        Config::Ecdsa { .. } => vec!["eid_der", "eid_ecdsa", "eid_hash", "eid_steps"],
        _ => vec!["eid_der", "eid_hash", "eid_rsa", "eid_steps"],
    };
    Ok((nargo_toml(&pkg, &deps, 5), main))
}

/// `Nargo.toml` and `main.nr` for one envelope step circuit.
fn envelope_circuit(md: Hash, dg: Hash, e: usize) -> (String, String) {
    let (mn, _, mf, _, _, _) = hash(md);
    let (dn, dd, df, _, _, _) = hash(dg);
    let oid = format!("OID_{}", dn.to_uppercase());
    let oid_len = if dg == Hash::Sha1 { 7 } else { 11 };
    // `nargo fmt` order: sorted, braces only for more than one name.
    let names = |a: &str, b: &str| {
        let mut v = vec![a.to_string(), b.to_string()];
        v.sort();
        v.dedup();
        if v.len() == 1 {
            v.remove(0)
        } else {
            format!("{{{}}}", v.join(", "))
        }
    };
    let fns = names(mf, df);
    let up = |h: &str| h.to_uppercase().replace("SHA", "SHA-");
    let main = format!(
        "//! Envelope step \u{b7} eContent {} \u{b7} data groups {} \u{b7} eContent \u{2264} {e} bytes.\n//!\n//! Generated by `eid-vectors circuits`; specification: docs/circuits/envelope.md.\n\nuse eid_hash::{fns};\nuse eid_steps::envelope::{{\n    assert_hash_at, assert_message_digest, check, flatten, {oid}, outputs, Witness,\n}};\nuse std::embedded_curve_ops::EmbeddedCurvePoint;\n\n/// Takes the proof date (unix seconds), the context the envelope is bound to\n/// (e.g. the transfer), the nullifier scope (0 for none) and the viewer key\n/// (fresh per transfer, never `(0, 0)`), and returns them with step B's\n/// commitment, the envelope and the nullifier through the databus\n/// (`envelope::flatten`), to the envelope kernel.\nfn main(\n    date: u64,\n    context: Field,\n    scope: Field,\n    viewers: [EmbeddedCurvePoint; 1],\n    w: Witness<{e}>,\n) -> return_data [Field; 16] {{\n    let p = check::<{e}, {oid_len}, {dd}>(date, w, {oid});\n    assert_message_digest(w, {mf}(w.econtent, p.lds.len));\n    assert_hash_at(w.econtent, p.lds.dg1_hash_at, {df}(w.dg1, p.dg1.len));\n    flatten(\n        date,\n        context,\n        scope,\n        viewers,\n        outputs(viewers, context, scope, w, p),\n    )\n}}\n",
        up(mn),
        up(dn),
    );
    (
        nargo_toml(&envelope_package(md, dg, e), &["eid_hash", "eid_steps"], 4),
        main,
    )
}

/// Sample proof date: 2026-09-27T00:00:00Z.
pub(crate) const SAMPLE_DATE: u64 = 1_790_467_200;

/// `Prover.toml` for every (eContent hash, data group hash) pair, from a
/// synthetic document. They alternate LDS v0 / v1 and whether the LDS also
/// lists DG11 (which step C ignores).
fn envelope_provers() -> Result<Vec<(PathBuf, String)>> {
    use crate::envelope::{field, sample_viewers, CONTEXT, DATA_KEY, EPHEMERAL, SCOPE};
    let mut out = vec![];
    let mut i = 0usize;
    for md in LDS_HASHES {
        for dg in LDS_HASHES {
            let lds = crate::mock::Lds {
                md_hash: md,
                dg_hash: dg,
                v1: i % 2 == 1,
                with_dg11: i % 3 != 2,
            };
            i += 1;
            let doc = crate::mock::Doc::build(
                Config::Ecdsa {
                    curve: "p256",
                    hash: Hash::Sha256,
                },
                lds,
                SAMPLE_COUNTRY,
                SAMPLE_EXPIRY,
            )?;
            let e = LDS_BUCKETS
                .into_iter()
                .find(|b| *b >= doc.econtent.len())
                .context("eContent fits no bucket")?;
            let digest = md.digest(&doc.econtent);
            let viewers = sample_viewers().map(|v| {
                let (x, y) = v.unwrap_or_default();
                (field(x), field(y))
            });
            let mut toml = String::from(
                "# Generated by `eid-vectors circuits` from a synthetic document (rust/eid-vectors/src/mock.rs). Do not edit.\n",
            );
            toml.push_str(&witness::envelope_toml(&witness::Envelope {
                econtent: &doc.econtent,
                bucket: e,
                digest: &digest,
                dg1: &doc.dg1,
                dg1_offset: doc.dg1_offset,
                sod_salt: "67890",
                country: SAMPLE_COUNTRY,
                date: i64::try_from(SAMPLE_DATE)?,
                context: &CONTEXT.to_string(),
                scope: &SCOPE.to_string(),
                viewers: &viewers,
                ephemeral: &EPHEMERAL.to_string(),
                key: &DATA_KEY.to_string(),
            })?);
            out.push((
                PathBuf::from(format!("{}/Prover.toml", envelope_dir(md, dg, e))),
                toml,
            ));
        }
    }
    Ok(out)
}

/// Salts and ids used by every sample Prover.toml.
pub(crate) const SAMPLE_COUNTRY: &str = "UTO";
pub(crate) const SAMPLE_EXPIRY: &str = "340415";

/// `Prover.toml` for every SOD configuration, from a synthetic document.
fn sod_provers() -> Result<Vec<(PathBuf, String)>> {
    let mut out = vec![];
    for &c in DSC_CONFIGS {
        let doc = crate::mock::Doc::new(c, SAMPLE_COUNTRY, SAMPLE_EXPIRY)?;
        let t = bucket(doc.tbs.len()).context("mock TBS fits no bucket")?;
        let sig = match &doc.dsc_key {
            PublicKey::Rsa { .. } => witness::Signature::Rsa(doc.signature.clone()),
            PublicKey::Ec { .. } => {
                let (r, s) = doc.signature.split_at(doc.signature.len() / 2);
                witness::Signature::Ecdsa {
                    r: r.to_vec(),
                    s: s.to_vec(),
                }
            }
        };
        let mut toml = String::from(
            "# Generated by `eid-vectors circuits` from a synthetic document (rust/eid-vectors/src/mock.rs). Do not edit.\n",
        );
        toml.push_str(&witness::sod_toml(
            &doc.tbs,
            &doc.attrs,
            doc.md_offset,
            &doc.dsc_key,
            &sig,
            "12345",
            3,
            SAMPLE_COUNTRY,
            "67890",
        )?);
        out.push((
            PathBuf::from(format!("{}/Prover.toml", c.step_dir("sod", t))),
            toml,
        ));
    }
    Ok(out)
}

/// Names of every bin package in the root Nargo.toml's workspace.
pub(crate) fn bin_packages() -> Result<Vec<String>> {
    let ws = std::fs::read_to_string(root().join("Nargo.toml"))?;
    let mut out = vec![];
    for member in ws
        .lines()
        .filter_map(|l| l.trim().strip_prefix('"')?.strip_suffix("\","))
    {
        let toml = std::fs::read_to_string(root().join(member).join("Nargo.toml"))?;
        if toml.contains("type = \"bin\"") {
            if let Some(name) = toml
                .lines()
                .find_map(|l| l.strip_prefix("name = \"")?.strip_suffix('"'))
            {
                out.push(name.to_string());
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Directory of a generated circuit package, from its name.
pub(crate) fn package_dir(pkg: &str) -> Option<String> {
    for &c in DSC_CONFIGS {
        for t in BUCKETS {
            for step in ["dsc", "sod"] {
                if c.step_package(step, t) == pkg {
                    return Some(c.step_dir(step, t));
                }
            }
        }
    }
    for md in LDS_HASHES {
        for dg in LDS_HASHES {
            for e in LDS_BUCKETS {
                if envelope_package(md, dg, e) == pkg {
                    return Some(envelope_dir(md, dg, e));
                }
            }
        }
    }
    None
}

/// Every generated file (relative path, contents), including the root Nargo.toml.
pub(crate) fn files() -> Result<Vec<(PathBuf, String)>> {
    let mut out = vec![];
    let mut members: Vec<String> = FIXED_MEMBERS.iter().map(|s| (*s).to_string()).collect();
    members.extend(bench_members()?);
    for &c in DSC_CONFIGS {
        for t in BUCKETS {
            let dir = c.dir(t);
            let (toml, main) = dsc_circuit(c, t)?;
            out.push((PathBuf::from(format!("{dir}/Nargo.toml")), toml));
            out.push((PathBuf::from(format!("{dir}/src/main.nr")), main));
            members.push(dir);
        }
    }
    for &c in DSC_CONFIGS {
        for t in BUCKETS {
            let dir = c.step_dir("sod", t);
            let (toml, main) = sod_circuit(c, t)?;
            out.push((PathBuf::from(format!("{dir}/Nargo.toml")), toml));
            out.push((PathBuf::from(format!("{dir}/src/main.nr")), main));
            members.push(dir);
        }
    }
    for md in LDS_HASHES {
        for dg in LDS_HASHES {
            for e in LDS_BUCKETS {
                let dir = envelope_dir(md, dg, e);
                let (toml, main) = envelope_circuit(md, dg, e);
                out.push((PathBuf::from(format!("{dir}/Nargo.toml")), toml));
                out.push((PathBuf::from(format!("{dir}/src/main.nr")), main));
                members.push(dir);
            }
        }
    }
    out.extend(provers()?);
    out.extend(sod_provers()?);
    out.extend(envelope_provers()?);
    let mut ws = String::from(
        "# Generated by `eid-vectors circuits` (libraries, benches, step circuits). Do not edit.\n[workspace]\nmembers = [\n",
    );
    for m in &members {
        writeln!(ws, "    \"{m}\",")?;
    }
    ws.push_str("]\n");
    out.push((PathBuf::from("Nargo.toml"), ws));
    Ok(out)
}

fn bench_members() -> Result<Vec<String>> {
    let mut v = vec![];
    for group in std::fs::read_dir(root().join("noir/bench"))? {
        let group = group?.path();
        if !group.is_dir() {
            continue;
        }
        for pkg in std::fs::read_dir(&group)? {
            let pkg = pkg?.path();
            if pkg.join("Nargo.toml").exists() {
                let rel = pkg
                    .strip_prefix(root())
                    .context("bench path")?
                    .to_string_lossy()
                    .to_string();
                v.push(rel);
            }
        }
    }
    v.sort();
    Ok(v)
}

/// `Prover.toml` for every fixture certificate whose configuration is
/// generated (first certificate per configuration), in its bucket's circuit.
fn provers() -> Result<Vec<(PathBuf, String)>> {
    let reg = registry()?;
    let mut out = vec![];
    let mut done: Vec<Config> = vec![];
    for (name, _) in RSA_CASES.iter().chain(ECDSA_CASES) {
        let cert = Cert::from_der(&std::fs::read(fixtures().join(format!("{name}.der")))?)?;
        let issuer = Cert::from_der(&std::fs::read(
            fixtures().join(format!("{name}.issuer.der")),
        )?)?;
        let key = issuer
            .key
            .clone()
            .map_err(|e| anyhow::anyhow!("{name}: {e}"))?;
        let Some(config) = Config::of(&cert, &key) else {
            continue;
        };
        if done.contains(&config) {
            continue;
        }
        done.push(config);
        let (tbs, ..) = csca_registry::der::signed_parts(&cert.der).context("signed parts")?;
        let t = bucket(tbs.len()).context("bucket")?;
        let key_id = hex::encode(sha2::Sha256::digest(key.material()));
        let mut toml =
            format!("# Generated by `eid-vectors circuits` from fixture {name}. Do not edit.\n");
        toml.push_str(&witness::dsc_toml(&reg, &key_id, &cert, "12345")?);
        out.push((
            PathBuf::from(format!("{}/Prover.toml", config.dir(t))),
            toml,
        ));
    }
    Ok(out)
}

/// Packages that get a Prover.toml (CI executes them).
pub(crate) fn sample_packages() -> Result<Vec<String>> {
    let envelopes = envelope_provers()?.into_iter().filter_map(|(p, _)| {
        let dir = p.parent()?.to_string_lossy().to_string();
        let mut parts = dir.strip_prefix("noir/circuits/envelope/")?.split('/');
        let (hashes, bucket) = (parts.next()?, parts.next()?.strip_prefix("lds_")?);
        Some(format!("envelope_{hashes}_lds{bucket}"))
    });
    Ok(provers()?
        .into_iter()
        .chain(sod_provers()?)
        .filter_map(|(p, _)| {
            let dir = p.parent()?.to_string_lossy().to_string();
            let t: usize = dir.rsplit("tbs_").next()?.parse().ok()?;
            let step = dir
                .strip_prefix("noir/circuits/")?
                .split('/')
                .next()?
                .to_string();
            let config = DSC_CONFIGS.iter().find(|c| c.step_dir(&step, t) == dir)?;
            Some(config.step_package(&step, t))
        })
        .chain(envelopes)
        .collect())
}
