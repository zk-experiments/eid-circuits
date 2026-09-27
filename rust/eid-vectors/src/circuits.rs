//! Generates the step circuits in `noir/circuits` and the root `Nargo.toml`.
//!
//! DSC step circuits are grouped by the CSCA's signature type
//! (`rsa_pkcs1v15`, `rsa_pss`, `ecdsa`), one per signing configuration seen in
//! the registry data (`DSC_CONFIGS`) and TBSCertificate size bucket. Each is a
//! thin binary: `eid_steps::dsc::check`, one hash, one signature check, the
//! commitment. A sample of them also gets a `Prover.toml` built from a real
//! certificate, which CI executes.

use crate::steps::{bucket, dsc_case, registry, BUCKETS};
use crate::{fixtures, root, ECDSA_CASES, RSA_CASES};
use anyhow::{bail, ensure, Context, Result};
use csca_registry::cert::Cert;
use csca_registry::crypto::{Hash, PublicKey, Scheme};
use num_bigint::BigUint;
use std::fmt::Write as _;
use std::path::PathBuf;

/// How a CSCA signs: key and scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Config {
    Pkcs1 { bits: u32, hash: Hash },
    Pss { bits: u32, hash: Hash, salt: usize },
    Ecdsa { curve: &'static str, hash: Hash },
}

/// Every (CSCA key, signature scheme) pair among verified signatures in the
/// DE + IT master lists (csca-registry fixtures), 2026-09-27.
pub(crate) const DSC_CONFIGS: &[Config] = &[
    Config::Ecdsa {
        curve: "p256",
        hash: Hash::Sha1,
    },
    Config::Ecdsa {
        curve: "p256",
        hash: Hash::Sha256,
    },
    Config::Ecdsa {
        curve: "p384",
        hash: Hash::Sha256,
    },
    Config::Ecdsa {
        curve: "p384",
        hash: Hash::Sha384,
    },
    Config::Ecdsa {
        curve: "p384",
        hash: Hash::Sha512,
    },
    Config::Ecdsa {
        curve: "p521",
        hash: Hash::Sha256,
    },
    Config::Ecdsa {
        curve: "p521",
        hash: Hash::Sha512,
    },
    Config::Ecdsa {
        curve: "bp256",
        hash: Hash::Sha1,
    },
    Config::Ecdsa {
        curve: "bp256",
        hash: Hash::Sha256,
    },
    Config::Ecdsa {
        curve: "bp256",
        hash: Hash::Sha512,
    },
    Config::Ecdsa {
        curve: "bp384",
        hash: Hash::Sha256,
    },
    Config::Ecdsa {
        curve: "bp384",
        hash: Hash::Sha384,
    },
    Config::Ecdsa {
        curve: "bp512",
        hash: Hash::Sha256,
    },
    Config::Ecdsa {
        curve: "bp512",
        hash: Hash::Sha512,
    },
    Config::Pkcs1 {
        bits: 2048,
        hash: Hash::Sha1,
    },
    Config::Pkcs1 {
        bits: 2048,
        hash: Hash::Sha256,
    },
    Config::Pkcs1 {
        bits: 2048,
        hash: Hash::Sha512,
    },
    Config::Pkcs1 {
        bits: 3072,
        hash: Hash::Sha256,
    },
    Config::Pkcs1 {
        bits: 3072,
        hash: Hash::Sha384,
    },
    Config::Pss {
        bits: 3072,
        hash: Hash::Sha256,
        salt: 32,
    },
    Config::Pss {
        bits: 3072,
        hash: Hash::Sha384,
        salt: 48,
    },
    Config::Pkcs1 {
        bits: 4096,
        hash: Hash::Sha1,
    },
    Config::Pkcs1 {
        bits: 4096,
        hash: Hash::Sha256,
    },
    Config::Pkcs1 {
        bits: 4096,
        hash: Hash::Sha384,
    },
    Config::Pkcs1 {
        bits: 4096,
        hash: Hash::Sha512,
    },
    Config::Pss {
        bits: 4096,
        hash: Hash::Sha256,
        salt: 20,
    },
    Config::Pss {
        bits: 4096,
        hash: Hash::Sha256,
        salt: 32,
    },
    Config::Pss {
        bits: 4096,
        hash: Hash::Sha384,
        salt: 48,
    },
    Config::Pss {
        bits: 4096,
        hash: Hash::Sha512,
        salt: 20,
    },
    Config::Pss {
        bits: 4096,
        hash: Hash::Sha512,
        salt: 64,
    },
    Config::Pkcs1 {
        bits: 6144,
        hash: Hash::Sha256,
    },
];

/// Library and bench packages, listed before the generated circuits.
const FIXED_MEMBERS: &[&str] = &[
    "noir/lib/hash",
    "noir/lib/rsa",
    "noir/lib/ecdsa",
    "noir/lib/der",
    "noir/lib/steps",
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

impl Config {
    /// Human-readable key and scheme, e.g. `RSA-4096 · PSS SHA-256 salt 32`.
    pub(crate) fn label(self) -> String {
        let up = |h: Hash| hash(h).0.to_uppercase().replace("SHA", "SHA-");
        match self {
            Config::Pkcs1 { bits, hash: h } => format!("RSA-{bits} \u{b7} PKCS#1 v1.5 {}", up(h)),
            Config::Pss {
                bits,
                hash: h,
                salt,
            } => format!("RSA-{bits} \u{b7} PSS {} salt {salt}", up(h)),
            Config::Ecdsa { curve, hash: h } => {
                let name = match curve {
                    "p256" => "P-256",
                    "p384" => "P-384",
                    "p521" => "P-521",
                    "bp256" => "brainpoolP256r1",
                    "bp384" => "brainpoolP384r1",
                    _ => "brainpoolP512r1",
                };
                format!("{name} \u{b7} ECDSA {}", up(h))
            }
        }
    }

    /// (group directory, variant directory)
    fn dirs(self) -> (&'static str, String) {
        match self {
            Config::Pkcs1 { bits, hash: h } => ("rsa_pkcs1v15", format!("{bits}_{}", hash(h).0)),
            Config::Pss {
                bits,
                hash: h,
                salt,
            } => ("rsa_pss", format!("{bits}_{}_s{salt}", hash(h).0)),
            Config::Ecdsa { curve, hash: h } => ("ecdsa", format!("{curve}_{}", hash(h).0)),
        }
    }

    pub(crate) fn package(self, t: usize) -> String {
        self.step_package("dsc", t)
    }

    fn dir(self, t: usize) -> String {
        self.step_dir("dsc", t)
    }

    /// Package of this configuration's circuit in `step` (`dsc`, `sod`).
    pub(crate) fn step_package(self, step: &str, t: usize) -> String {
        let (g, v) = self.dirs();
        format!("{step}_{g}_{v}_tbs{t}")
    }

    fn step_dir(self, step: &str, t: usize) -> String {
        let (g, v) = self.dirs();
        format!("noir/circuits/{step}/{g}/{v}/tbs_{t}")
    }

    /// The configuration a certificate was signed with, if generated.
    pub(crate) fn of(cert: &Cert, issuer_key: &PublicKey) -> Option<Self> {
        let scheme = cert.scheme.clone().ok()?;
        let found = match (scheme, issuer_key) {
            (Scheme::RsaPkcs1(h), PublicKey::Rsa { .. }) => Config::Pkcs1 {
                bits: u32::try_from(issuer_key.bits()).ok()?,
                hash: h,
            },
            (Scheme::RsaPss { hash: h, salt, .. }, PublicKey::Rsa { .. }) => Config::Pss {
                bits: u32::try_from(issuer_key.bits()).ok()?,
                hash: h,
                salt,
            },
            (
                Scheme::Ecdsa {
                    hash: h,
                    plain: false,
                },
                PublicKey::Ec { curve: Some(c), .. },
            ) => {
                let label = match c.name() {
                    "P-256" => "p256",
                    "P-384" => "p384",
                    "P-521" => "p521",
                    "brainpoolP256r1" => "bp256",
                    "brainpoolP384r1" => "bp384",
                    "brainpoolP512r1" => "bp512",
                    _ => return None,
                };
                Config::Ecdsa {
                    curve: label,
                    hash: h,
                }
            }
            _ => return None,
        };
        DSC_CONFIGS.contains(&found).then_some(found)
    }
}

fn nargo_toml(package: &str, deps: &[&str]) -> String {
    let mut s = format!(
        "[package]\nname = \"{package}\"\ntype = \"bin\"\nauthors = [\"zk-experiments\"]\ncompiler_version = \">=1.0.0\"\n\n[dependencies]\n"
    );
    for d in deps {
        writeln!(
            s,
            "{d} = {{ path = \"../../../../../lib/{}\" }}",
            d.trim_start_matches("eid_")
        )
        .ok();
    }
    s.push_str(
        "csca_registry = { tag = \"v0.3.0\", git = \"https://github.com/zk-experiments/csca-registry\", directory = \"noir/csca_registry\" }\n",
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
                "//! DSC step \u{b7} {title} \u{b7} TBSCertificate \u{2264} {t} bytes.\n//!\n//! Generated by `eid-vectors circuits`; specification: docs/circuits/dsc.md.\n\n{uses}\nuse eid_steps::dsc::{{check, commitment, KeyKind, Witness}};\nuse eid_steps::{id};\n\n/// Public: registry root. Returns `[commitment, hash id]`.\nfn main(\n    root: pub Field,\n    salt: Field,\n    w: Witness<{t}, {k}>,\n    redc: [u128; {limbs}],\n    signature: [u8; {k}],\n) -> pub [Field; 2] {{\n    let f = check::<{t}, {k}, {m}>(root, w, KeyKind {{ key_type: 1, curve: 0, bits: {bits} }});\n    let digest = {hf}(w.tbs, f.len);\n    {call}\n    [commitment(salt, w.header.country, {id}, w.tbs, f.len), {id} as Field]\n}}\n"
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
                "//! DSC step \u{b7} ECDSA \u{b7} {label} \u{b7} {} \u{b7} TBSCertificate \u{2264} {t} bytes.\n//!\n//! Generated by `eid-vectors circuits`; specification: docs/circuits/dsc.md.\n\nuse eid_ecdsa::{wrapper};\nuse eid_hash::{hf};\nuse eid_steps::dsc::{{check, commitment, KeyKind, Witness}};\nuse eid_steps::{id};\n\n/// Public: registry root. Returns `[commitment, hash id]`.\nfn main(\n    root: pub Field,\n    salt: Field,\n    w: Witness<{t}, {k}>,\n    r: [u8; {sz}],\n    s: [u8; {sz}],\n) -> pub [Field; 2] {{\n    let f = check::<{t}, {k}, {m}>(root, w, KeyKind {{ key_type: 2, curve: {curve_id}, bits: {bits} }});\n    let mut x: [u8; {sz}] = [0; {sz}];\n    let mut y: [u8; {sz}] = [0; {sz}];\n    for i in 0..{sz} {{\n        x[i] = w.csca_key[i];\n        y[i] = w.csca_key[{sz} + i];\n    }}\n    {wrapper}::<{d}>(x, y, r, s, {hf}(w.tbs, f.len));\n    [commitment(salt, w.header.country, {id}, w.tbs, f.len), {id} as Field]\n}}\n",
                hn.to_uppercase()
            );
            (main, vec!["eid_ecdsa", "eid_hash", "eid_steps"])
        }
    };
    Ok((nargo_toml(&pkg, &deps), main))
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
    let (_, _, _, _, _, id) = hash(match c {
        Config::Pkcs1 { hash, .. } | Config::Pss { hash, .. } | Config::Ecdsa { hash, .. } => hash,
    });
    let (uses, params, verify) = sod_verify(c)?;
    let verify = verify.replace("spki_rsa::<T,", &format!("spki_rsa::<{t},"));
    let main = format!(
        "//! SOD step \u{b7} {} \u{b7} DSC TBSCertificate \u{2264} {t} bytes.\n//!\n//! Generated by `eid-vectors circuits`; specification: docs/circuits/sod.md.\n\n{uses}\nuse eid_steps::{{dsc, sod}};\nuse eid_steps::{id};\n\n/// Returns `[DSC commitment, SOD commitment, hash id]`. The first must equal\n/// the DSC step's output.\nfn main(\n    dsc_salt: Field,\n    dsc_hash_id: u8,\n    country: [u8; 3],\n    salt: Field,\n    tbs: [u8; {t}],\n    attrs: [u8; 256],\n    md_offset: u32,\n{params}) -> pub [Field; 3] {{\n    let (f, a) = sod::parse(tbs, attrs, md_offset);\n    {verify}\n    [\n        dsc::commitment(dsc_salt, country, dsc_hash_id, tbs, f.len),\n        sod::commitment(salt, country, a),\n        {id} as Field,\n    ]\n}}\n",
        c.label()
    );
    let deps: Vec<&str> = match c {
        Config::Ecdsa { .. } => vec!["eid_der", "eid_ecdsa", "eid_hash", "eid_steps"],
        _ => vec!["eid_der", "eid_hash", "eid_rsa", "eid_steps"],
    };
    Ok((nargo_toml(&pkg, &deps), main))
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
        let mut tbs = doc.tbs.clone();
        tbs.resize(t, 0);
        let mut attrs = doc.attrs.clone();
        ensure!(attrs.len() <= 256, "mock signedAttrs exceed the bucket");
        attrs.resize(256, 0);
        let mut toml = String::from(
            "# Generated by `eid-vectors circuits` from a synthetic document (rust/eid-vectors/src/mock.rs). Do not edit.\n",
        );
        writeln!(
            toml,
            "dsc_salt = \"12345\"\ndsc_hash_id = 3\ncountry = {}\nsalt = \"67890\"\ntbs = {}\nattrs = {}\nmd_offset = {}",
            toml_bytes(SAMPLE_COUNTRY.as_bytes()),
            toml_bytes(&tbs),
            toml_bytes(&attrs),
            doc.md_offset
        )?;
        match &doc.dsc_key {
            PublicKey::Rsa { n, .. } => {
                let modulus = BigUint::from_bytes_be(n);
                let bits = usize::try_from(modulus.bits())?;
                let redc = (BigUint::from(1u8) << (2 * bits + 6)) / &modulus;
                let mask = (BigUint::from(1u8) << 120u32) - 1u8;
                let r: Vec<String> = (0..bits.div_ceil(120))
                    .map(|i| format!("\"0x{:x}\"", (&redc >> (120 * i)) & &mask))
                    .collect();
                writeln!(
                    toml,
                    "redc = [{}]\nsignature = {}",
                    r.join(", "),
                    toml_bytes(&doc.signature)
                )?;
            }
            PublicKey::Ec { .. } => {
                let (r, s) = doc.signature.split_at(doc.signature.len() / 2);
                writeln!(toml, "r = {}\ns = {}", toml_bytes(r), toml_bytes(s))?;
            }
        }
        out.push((
            PathBuf::from(format!("{}/Prover.toml", c.step_dir("sod", t))),
            toml,
        ));
    }
    Ok(out)
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
    out.extend(provers()?);
    out.extend(sod_provers()?);
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

fn toml_bytes(b: &[u8]) -> String {
    let body: Vec<String> = b.iter().map(|x| x.to_string()).collect();
    format!("[{}]", body.join(", "))
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
        let dc = dsc_case(&reg, name)?;
        let (tbs, _, _, sig) =
            csca_registry::der::signed_parts(&cert.der).context("signed parts")?;
        let t = bucket(tbs.len()).context("bucket")?;
        let mut toml =
            format!("# Generated by `eid-vectors circuits` from fixture {name}. Do not edit.\n");
        writeln!(toml, "root = \"{}\"\nsalt = \"12345\"", reg.commitment.root)?;
        match &key {
            PublicKey::Rsa { n, .. } => {
                let modulus = BigUint::from_bytes_be(n);
                let bits = usize::try_from(modulus.bits())?;
                let limbs = bits.div_ceil(120);
                let redc = (BigUint::from(1u8) << (2 * bits + 6)) / &modulus;
                let mask = (BigUint::from(1u8) << 120u32) - 1u8;
                let r: Vec<String> = (0..limbs)
                    .map(|i| format!("\"0x{:x}\"", (&redc >> (120 * i)) & &mask))
                    .collect();
                let mut signature = vec![0u8; n.len() - sig.len()];
                signature.extend_from_slice(sig);
                writeln!(
                    toml,
                    "redc = [{}]\nsignature = {}",
                    r.join(", "),
                    toml_bytes(&signature)
                )?;
            }
            PublicKey::Ec { point, .. } => {
                let sz = (point.len() - 1) / 2;
                let (seq, _) = csca_registry::der::expect(sig, 0x30).context("ECDSA signature")?;
                let parts = csca_registry::der::children(seq.content).context("ECDSA signature")?;
                let [r, s] = parts.as_slice() else {
                    bail!("{name}: signature is not (r, s)")
                };
                let pad = |v: &[u8]| {
                    let v = csca_registry::der::uint(v);
                    let mut o = vec![0u8; sz - v.len()];
                    o.extend_from_slice(v);
                    o
                };
                writeln!(
                    toml,
                    "r = {}\ns = {}",
                    toml_bytes(&pad(r.content)),
                    toml_bytes(&pad(s.content))
                )?;
            }
        }
        toml.push_str(&witness_toml(&dc.witness_parts));
        out.push((
            PathBuf::from(format!("{}/Prover.toml", config.dir(t))),
            toml,
        ));
    }
    Ok(out)
}

/// The `w` table of a Prover.toml.
fn witness_toml(p: &crate::steps::WitnessParts) -> String {
    let path = |idx: &str, sib: &[String]| {
        format!(
            "index = \"{idx}\"\nsiblings = [{}]\n",
            sib.iter()
                .map(|s| format!("\"{s}\""))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let mut s = String::new();
    s.push_str(&format!(
        "\n[w]\ntbs = {}\ncsca_key = {}\nrevocations_root = \"{}\"\n",
        toml_bytes(&p.tbs),
        toml_bytes(&p.csca_key),
        p.revocations_root
    ));
    let h = &p.header;
    s.push_str(&format!(
        "\n[w.header]\ncountry = {}\nkey_type = {}\ncurve = {}\nbits = {}\nexponent = {}\nopen = \"{}\"\nclose = \"{}\"\n",
        toml_bytes(&h.country), h.key_type, h.curve, h.bits, h.exponent, h.open, h.close
    ));
    s.push_str(&format!(
        "\n[w.key_path]\n{}",
        path(&p.key_index, &p.key_siblings)
    ));
    s.push_str(&format!(
        "\n[w.not_revoked]\nhas_lower = {}\nlower_leaf = \"{}\"\nupper_leaf = \"{}\"\n",
        p.has_lower, p.lower_leaf, p.upper_leaf
    ));
    s.push_str(&format!(
        "\n[w.not_revoked.lower]\n{}",
        path(&p.lower_index, &p.lower_siblings)
    ));
    s.push_str(&format!(
        "\n[w.not_revoked.upper]\n{}",
        path(&p.upper_index, &p.upper_siblings)
    ));
    s
}

/// Packages that get a Prover.toml (CI executes them).
pub(crate) fn sample_packages() -> Result<Vec<String>> {
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
        .collect())
}
