//! Test-vector generator for eid-circuits.
//!
//! ```text
//! eid-vectors extract --sources <csca-registry>/tests/fixtures/sources   # refresh fixtures/*.der
//! eid-vectors rsa                                                         # write noir/lib/rsa/src/vectors.nr
//! eid-vectors rsa --check                                                 # fail if it is stale (CI)
//! eid-vectors ecdsa [--check]                                             # noir/lib/ecdsa/src/vectors.nr
//! eid-vectors der [--check]                                               # noir/lib/der/src/{vectors,curves}.nr
//! eid-vectors steps [--check]                                             # noir/lib/steps/src/{vectors,sod_vectors,envelope_vectors}.nr
//! eid-vectors envelope [--check]                                          # noir/lib/envelope/src/vectors.nr
//! eid-vectors circuits [--check]                                          # noir/circuits/**, Prover.toml samples, root Nargo.toml
//! eid-vectors samples                                                     # print packages that have a Prover.toml
//! eid-vectors costs [--check]                                             # docs/COSTS.md from docs/data + fixtures
//! eid-vectors curves [--check]                                            # vendored noir_bigcurve curves/eid_*.nr
//! ```
//!
//! Every vector is a real CSCA certificate from a master list, checked with
//! csca-registry's RustCrypto verifier before it is emitted.

mod circuits;
mod costs;
mod curve_params;
mod curves;
mod ec;
mod envelope;
mod mock;
mod steps;

use anyhow::{bail, ensure, Context, Result};
use clap::{Parser, Subcommand};
use csca_registry::cert::Cert;
use csca_registry::crypto::{Hash, PublicKey, Scheme};
use csca_registry::{der, masterlist};
use num_bigint::BigUint;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// RSA cases: (name, certificate fingerprint prefix). One per scheme, hash,
/// salt and modulus size seen in the DE + IT master lists, plus exponent 3
/// and a 17-bit exponent.
pub(crate) const RSA_CASES: &[(&str, &str)] = &[
    ("pkcs1_sha1_4096_cn", "72b3f2a0afdb41da"),
    ("pkcs1_sha1_2048_sm", "158eb79cf1f7ba1e"),
    ("pkcs1_sha256_4096_ad", "73d1823ab0ff3190"),
    ("pkcs1_sha256_3072_ar", "506c8c4d63ff620a"),
    ("pkcs1_sha256_2048_is", "a920114e6cb67daa"),
    ("pkcs1_sha256_6144_md", "3940be14e099bea4"),
    ("pkcs1_sha384_4096_ad", "98145fc6b84d7fc7"),
    ("pkcs1_sha384_3072_tj", "15ba4cda8df1e877"),
    ("pkcs1_sha512_4096_au", "ada50615a76e6791"),
    ("pkcs1_sha512_2048_is", "0b727ad22308e397"),
    ("pkcs1_sha256_4096_e107903_ng", "7fd6408e91c935ef"),
    ("pss_sha256_s20_4096_il", "0c7e858d3c1cf472"),
    ("pss_sha256_s32_4096_ag", "6974f02662049ba8"),
    ("pss_sha256_s32_3072_cz", "7fd675743a210314"),
    ("pss_sha256_s32_4096_e3_cn", "c5de9c6e15118bda"),
    ("pss_sha384_s48_4096_eu", "ba2025b7f2e8c508"),
    ("pss_sha384_s48_3072_mk", "ee76078835bec161"),
    ("pss_sha512_s20_4096_ee", "75cac2bcf65fcba8"),
    ("pss_sha512_s64_4096_ee", "f05b6dddc5ef5748"),
];

/// ECDSA cases: one per curve and hash seen in the DE + IT master lists.
pub(crate) const ECDSA_CASES: &[(&str, &str)] = &[
    ("ecdsa_sha1_bp256_lt", "39f42ac25c8e712b"),
    ("ecdsa_sha1_p256_ru", "796bfca7304e9451"),
    ("ecdsa_sha256_p256_be", "e26a11b216d5f296"),
    ("ecdsa_sha256_p384_ae", "d0e477b5de01ee68"),
    ("ecdsa_sha256_p521_lt", "06c6b8ac119c4fb2"),
    ("ecdsa_sha256_bp256_ae", "3bbf823a2c632b7d"),
    ("ecdsa_sha256_bp384_jo", "a5ca4dfa075f2f71"),
    ("ecdsa_sha256_bp512_ng", "aac085e8a0bece54"),
    ("ecdsa_sha384_p384_bm", "a80405f9bec57701"),
    ("ecdsa_sha384_bp384_ao", "f0822a8b994f91e4"),
    ("ecdsa_sha512_p384_dz", "cb0a54d956fd05b7"),
    ("ecdsa_sha512_p521_eg", "b93296ab3c2ef444"),
    ("ecdsa_sha512_bp256_ba", "2d8b9dc03d5629c8"),
    ("ecdsa_sha512_bp512_br", "e186fd79a9aa73e2"),
];

/// Exponent bound used by the generated tests (all exponents in the data fit).
const E_BITS: u32 = 17;

#[derive(Debug, Parser)]
#[command(name = "eid-vectors", about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Copy the case certificates (and their issuers) out of master lists
    Extract {
        /// Directory with `XX_*.ml` master lists (csca-registry tests/fixtures/sources)
        #[arg(long)]
        sources: PathBuf,
    },
    /// Generate noir/lib/rsa/src/vectors.nr from the fixtures
    Rsa {
        /// Fail instead of writing when the file is stale
        #[arg(long)]
        check: bool,
    },
    /// Generate noir/lib/ecdsa/src/vectors.nr from the fixtures
    Ecdsa {
        /// Fail instead of writing when the file is stale
        #[arg(long)]
        check: bool,
    },
    /// Generate noir/lib/der/src/vectors.nr (TBSCertificate walks) from the fixtures
    Der {
        /// Fail instead of writing when the file is stale
        #[arg(long)]
        check: bool,
    },
    /// Generate noir/lib/steps/src/vectors.nr (DSC step checks) from the fixtures
    Steps {
        /// Fail instead of writing when the file is stale
        #[arg(long)]
        check: bool,
    },
    /// Generate noir/lib/envelope/src/vectors.nr with rust/eid-envelope
    Envelope {
        /// Fail instead of writing when the file is stale
        #[arg(long)]
        check: bool,
    },
    /// Generate the step circuits, their Prover.toml samples and the root Nargo.toml
    Circuits {
        /// Fail instead of writing when a file is stale
        #[arg(long)]
        check: bool,
    },
    /// Generate docs/COSTS.md (per-country proving costs) from docs/data and the fixtures
    Costs {
        /// Fail instead of writing when the file is stale
        #[arg(long)]
        check: bool,
    },
    /// Print the packages that have a Prover.toml (executed in CI)
    Samples,
    /// Generate the vendored noir_bigcurve curves/eid_*.nr (fields and curve parameters)
    Curves {
        /// Fail instead of writing when a file is stale
        #[arg(long)]
        check: bool,
    },
}

pub(crate) fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

pub(crate) fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Extract { sources } => extract(&sources),
        Command::Rsa { check } => {
            write_or_check(&root().join("noir/lib/rsa/src/vectors.nr"), &rsa()?, check)
        }
        Command::Ecdsa { check } => write_or_check(
            &root().join("noir/lib/ecdsa/src/vectors.nr"),
            &ecdsa()?,
            check,
        ),
        Command::Der { check } => {
            write_or_check(
                &root().join("noir/lib/der/src/curves.nr"),
                &curves::der_curves_module()?,
                check,
            )?;
            write_or_check(
                &root().join("noir/lib/der/src/vectors.nr"),
                &der_vectors()?,
                check,
            )
        }
        Command::Steps { check } => {
            write_or_check(
                &root().join("noir/lib/steps/src/vectors.nr"),
                &steps::steps_vectors()?,
                check,
            )?;
            write_or_check(
                &root().join("noir/lib/steps/src/sod_vectors.nr"),
                &steps::sod_vectors()?,
                check,
            )?;
            write_or_check(
                &root().join("noir/lib/steps/src/envelope_vectors.nr"),
                &steps::envelope_vectors()?,
                check,
            )
        }
        Command::Envelope { check } => write_or_check(
            &root().join("noir/lib/envelope/src/vectors.nr"),
            &envelope::vectors()?,
            check,
        ),
        Command::Circuits { check } => {
            for (rel, contents) in circuits::files()? {
                let path = root().join(rel);
                if let Some(dir) = path.parent() {
                    std::fs::create_dir_all(dir)?;
                }
                write_or_check(&path, &contents, check)?;
            }
            Ok(())
        }
        Command::Costs { check } => {
            write_or_check(&root().join("docs/COSTS.md"), &costs::report()?, check)
        }
        Command::Samples => {
            use std::io::Write as _;
            let mut stdout = std::io::stdout().lock();
            for p in circuits::sample_packages()? {
                writeln!(stdout, "{p}")?;
            }
            Ok(())
        }
        Command::Curves { check } => {
            for (name, prefix, strukt) in curves::GENERATED {
                let path = root().join(format!(
                    "noir/vendor/noir_bigcurve/src/curves/eid_{prefix}.nr"
                ));
                write_or_check(&path, &curves::module(name, prefix, strukt)?, check)?;
            }
            Ok(())
        }
    }
}

/// Loads every master list under `sources` and writes each case certificate
/// and its issuer to `fixtures/<name>.der` / `fixtures/<name>.issuer.der`.
fn extract(sources: &Path) -> Result<()> {
    let mut certs: Vec<Cert> = vec![];
    for entry in std::fs::read_dir(sources)? {
        let path = entry?.path();
        if path.extension().is_some_and(|e| e == "ml") {
            let country: String = path
                .file_name()
                .map(|f| f.to_string_lossy().chars().take(2).collect())
                .unwrap_or_default();
            certs.extend(masterlist::load(&std::fs::read(&path)?, &country.to_uppercase())?.certs);
        }
    }
    std::fs::create_dir_all(fixtures())?;
    for (name, prefix) in RSA_CASES.iter().chain(ECDSA_CASES) {
        let cert = certs
            .iter()
            .find(|c| c.fingerprint.starts_with(prefix))
            .with_context(|| format!("{name}: no certificate {prefix}"))?;
        let issuer = certs
            .iter()
            .find(|i| i.key.as_ref().is_ok_and(|k| cert.verify_with(k).is_ok()))
            .with_context(|| format!("{name}: no issuer verifies {prefix}"))?;
        std::fs::write(fixtures().join(format!("{name}.der")), &cert.der)?;
        std::fs::write(fixtures().join(format!("{name}.issuer.der")), &issuer.der)?;
    }
    Ok(())
}

pub(crate) fn bytes(b: &[u8]) -> String {
    let body: Vec<String> = b.iter().map(|x| format!("0x{x:02x}")).collect();
    format!("[{}]", body.join(", "))
}

/// 120-bit little-endian limbs of `x`.
fn limbs(x: &BigUint, n: usize) -> String {
    let mask = (BigUint::from(1u8) << 120u32) - 1u8;
    let body: Vec<String> = (0..n)
        .map(|i| format!("0x{:x}", (x >> (120 * i)) & &mask))
        .collect();
    format!("[{}]", body.join(", "))
}

fn hash_info(h: Hash) -> (&'static str, usize, &'static str, &'static str) {
    match h {
        Hash::Sha1 => ("sha1_var", 20, "DIGEST_INFO_SHA1", "Sha1"),
        Hash::Sha224 => ("sha224_var", 28, "DIGEST_INFO_SHA224", "Sha224"),
        Hash::Sha256 => ("sha256_var", 32, "DIGEST_INFO_SHA256", "Sha256"),
        Hash::Sha384 => ("sha384_var", 48, "DIGEST_INFO_SHA384", "Sha384"),
        Hash::Sha512 => ("sha512_var", 64, "DIGEST_INFO_SHA512", "Sha512"),
    }
}

fn rsa() -> Result<String> {
    let mut out = String::from(
        "// Generated by `eid-vectors rsa` from rust/eid-vectors/fixtures. Do not edit.\n\
         // Each case is a real CSCA certificate signature, verified with RustCrypto\n\
         // (csca-registry) before emission.\n\n\
         use crate::{\n    DIGEST_INFO_SHA1, DIGEST_INFO_SHA256, DIGEST_INFO_SHA384, DIGEST_INFO_SHA512, verify_pkcs1v15,\n    verify_pss,\n};\n\
         use eid_hash::{sha1_var, Sha256, sha256_var, Sha384, sha384_var, Sha512, sha512_var};\n\n",
    );
    for (name, _) in RSA_CASES {
        let cert = Cert::from_der(&std::fs::read(fixtures().join(format!("{name}.der")))?)?;
        let issuer = Cert::from_der(&std::fs::read(
            fixtures().join(format!("{name}.issuer.der")),
        )?)?;
        let key = issuer
            .key
            .clone()
            .map_err(|e| anyhow::anyhow!("{name}: issuer key {e}"))?;
        cert.verify_with(&key)
            .map_err(|e| anyhow::anyhow!("{name}: {e}"))?;
        let PublicKey::Rsa { n, e } = &key else {
            bail!("{name}: issuer key is not RSA")
        };
        let scheme = cert
            .scheme
            .clone()
            .map_err(|e| anyhow::anyhow!("{name}: {e}"))?;
        let (tbs, _, _, sig) = der::signed_parts(&cert.der).context("signed parts")?;

        let modulus = BigUint::from_bytes_be(n);
        let bits = usize::try_from(modulus.bits())?;
        ensure!(
            bits % 8 == 0,
            "{name}: modulus is {bits} bits, not a multiple of 8"
        );
        let k = bits / 8;
        let limb_count = bits.div_ceil(120);
        let redc = (BigUint::from(1u8) << (2 * bits + 6)) / &modulus;
        let mut signature = vec![0u8; k - sig.len()];
        signature.extend_from_slice(sig);
        let exponent = e.iter().fold(0u64, |a, b| a << 8 | u64::from(*b));
        ensure!(
            exponent < 1 << E_BITS,
            "{name}: exponent {exponent} exceeds E_BITS"
        );

        let up = name.to_uppercase();
        writeln!(
            out,
            "// {name}: {} signed by RSA-{bits} (e = {exponent}); certificate {}",
            scheme.name(),
            cert.fingerprint
        )?;
        writeln!(
            out,
            "pub(crate) global {up}_MODULUS: [u8; {k}] = {};",
            bytes(n)
        )?;
        writeln!(
            out,
            "pub(crate) global {up}_REDC: [u128; {limb_count}] = {};",
            limbs(&redc, limb_count)
        )?;
        writeln!(out, "pub(crate) global {up}_EXPONENT: u32 = {exponent};")?;
        writeln!(
            out,
            "pub(crate) global {up}_TBS: [u8; {}] = {};",
            tbs.len(),
            bytes(tbs)
        )?;
        writeln!(
            out,
            "pub(crate) global {up}_SIGNATURE: [u8; {k}] = {};",
            bytes(&signature)
        )?;
        let call = match scheme {
            Scheme::RsaPkcs1(h) => {
                let (f, d, info, _) = hash_info(h);
                let p = if h == Hash::Sha1 { 15 } else { 19 };
                format!(
                    "verify_pkcs1v15::<{limb_count}, {bits}, {E_BITS}, {d}, {p}>(\n        {up}_MODULUS,\n        {up}_REDC,\n        {up}_EXPONENT,\n        {up}_SIGNATURE,\n        {f}({up}_TBS, {}),\n        {info},\n    );",
                    tbs.len()
                )
            }
            Scheme::RsaPss { hash, mgf, salt } => {
                ensure!(hash == mgf, "{name}: MGF1 hash differs from message hash");
                let (f, d, _, ty) = hash_info(hash);
                format!(
                    "verify_pss::<{ty}, {limb_count}, {bits}, {E_BITS}, {d}, {salt}>(\n        {up}_MODULUS,\n        {up}_REDC,\n        {up}_EXPONENT,\n        {up}_SIGNATURE,\n        {f}({up}_TBS, {}),\n    );",
                    tbs.len()
                )
            }
            Scheme::Ecdsa { .. } => bail!("{name}: not an RSA scheme"),
        };
        writeln!(out, "#[test]\nfn {name}() {{\n    {call}\n}}\n")?;
    }
    Ok(out)
}

/// Noir wrapper, coordinate bytes and scalar bytes per curve.
fn curve_info(name: &str) -> Result<(&'static str, usize, usize)> {
    Ok(match name {
        "P-256" => ("verify_p256", 32, 32),
        "P-384" => ("verify_p384", 48, 48),
        "P-521" => ("verify_p521", 66, 66),
        "brainpoolP256r1" => ("verify_bp256", 32, 32),
        "brainpoolP384r1" => ("verify_bp384", 48, 48),
        "brainpoolP512r1" => ("verify_bp512", 64, 64),
        other => bail!("no ECDSA wrapper for {other}"),
    })
}

fn left_pad(b: &[u8], size: usize) -> Result<Vec<u8>> {
    let b = der::uint(b);
    ensure!(b.len() <= size, "value longer than {size} bytes");
    let mut out = vec![0u8; size - b.len()];
    out.extend_from_slice(b);
    Ok(out)
}

fn ecdsa() -> Result<String> {
    let mut out = String::from(
        "// Generated by `eid-vectors ecdsa` from rust/eid-vectors/fixtures. Do not edit.\n\
         // Each case is a real CSCA certificate signature, verified with RustCrypto\n\
         // (csca-registry) before emission.\n\n\
         use crate::{verify_bp256, verify_bp384, verify_bp512, verify_p256, verify_p384, verify_p521};\n\
         use eid_hash::{sha1_var, sha256_var, sha384_var, sha512_var};\n\n",
    );
    for (name, _) in ECDSA_CASES {
        let cert = Cert::from_der(&std::fs::read(fixtures().join(format!("{name}.der")))?)?;
        let issuer = Cert::from_der(&std::fs::read(
            fixtures().join(format!("{name}.issuer.der")),
        )?)?;
        let key = issuer
            .key
            .clone()
            .map_err(|e| anyhow::anyhow!("{name}: issuer key {e}"))?;
        cert.verify_with(&key)
            .map_err(|e| anyhow::anyhow!("{name}: {e}"))?;
        let PublicKey::Ec {
            curve: Some(curve),
            point,
        } = &key
        else {
            bail!("{name}: issuer key is not a named-curve EC key")
        };
        let Scheme::Ecdsa { hash, plain: false } = cert
            .scheme
            .clone()
            .map_err(|e| anyhow::anyhow!("{name}: {e}"))?
        else {
            bail!("{name}: not a DER ECDSA signature")
        };
        let (tbs, _, _, sig) = der::signed_parts(&cert.der).context("signed parts")?;
        let (seq, _) = der::expect(sig, 0x30).context("ECDSA signature SEQUENCE")?;
        let parts = der::children(seq.content).context("ECDSA signature")?;
        let [r, s] = parts.as_slice() else {
            bail!("{name}: signature is not (r, s)")
        };
        let (wrapper, coord, scalar) = curve_info(curve.name())?;
        ensure!(
            point.len() == 1 + 2 * coord && point[0] == 4,
            "{name}: point is not uncompressed"
        );
        let (x, y) = point[1..].split_at(coord);
        let (f, d, _, _) = hash_info(hash);
        let up = name.to_uppercase();
        writeln!(
            out,
            "// {name}: ecdsa-{} on {}; certificate {}",
            hash.name(),
            curve.name(),
            cert.fingerprint
        )?;
        writeln!(
            out,
            "pub(crate) global {up}_X: [u8; {coord}] = {};",
            bytes(x)
        )?;
        writeln!(
            out,
            "pub(crate) global {up}_Y: [u8; {coord}] = {};",
            bytes(y)
        )?;
        writeln!(
            out,
            "pub(crate) global {up}_R: [u8; {scalar}] = {};",
            bytes(&left_pad(r.content, scalar)?)
        )?;
        writeln!(
            out,
            "pub(crate) global {up}_S: [u8; {scalar}] = {};",
            bytes(&left_pad(s.content, scalar)?)
        )?;
        writeln!(
            out,
            "pub(crate) global {up}_TBS: [u8; {}] = {};",
            tbs.len(),
            bytes(tbs)
        )?;
        writeln!(
            out,
            "#[test]\nfn {name}() {{\n    {wrapper}::<{d}>({up}_X, {up}_Y, {up}_R, {up}_S, {f}({up}_TBS, {}));\n}}\n",
            tbs.len()
        )?;
    }
    Ok(out)
}

/// TBSCertificate walks: for every fixture certificate, the serial and
/// validity x509-parser reads must be what `eid_der::parse_tbs` reads.
fn der_vectors() -> Result<String> {
    let mut out = String::from(
        "// Generated by `eid-vectors der` from rust/eid-vectors/fixtures. Do not edit.\n\
         // Expected values come from x509-parser (via csca-registry).\n\n\
         use crate::{curves, parse_tbs, spki_ec, spki_rsa};\n\n",
    );
    for (name, _) in RSA_CASES.iter().chain(ECDSA_CASES) {
        let cert = Cert::from_der(&std::fs::read(fixtures().join(format!("{name}.der")))?)?;
        let (tbs, _, _, _) = der::signed_parts(&cert.der).context("signed parts")?;
        ensure!(
            cert.serial.len() <= 20,
            "{name}: serial longer than 20 bytes"
        );
        let mut serial = vec![0u8; 20 - cert.serial.len()];
        serial.extend_from_slice(&cert.serial);
        let up = name.to_uppercase();
        writeln!(
            out,
            "pub(crate) global {up}_TBS: [u8; {}] = {};",
            tbs.len(),
            bytes(tbs)
        )?;
        writeln!(
            out,
            "#[test]\nfn {name}() {{\n    let f = parse_tbs({up}_TBS);\n    assert_eq(f.len, {});\n    assert_eq(f.serial, {});\n    assert_eq(f.not_before, {});\n    assert_eq(f.not_after, {});\n}}\n",
            tbs.len(),
            bytes(&serial),
            cert.not_before,
            cert.not_after,
        )?;
        // The certificate's own key, as csca-registry's parser reads it.
        let key = cert
            .key
            .clone()
            .map_err(|e| anyhow::anyhow!("{name}: {e}"))?;
        let check = match &key {
            PublicKey::Rsa { n, e } => {
                ensure!(e.len() <= 4, "{name}: exponent longer than 4 bytes");
                let exponent = e.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
                format!(
                    "    let (n, e) = spki_rsa::<{}, {}>({up}_TBS, f.spki_offset, f.len);\n    assert_eq(n, {});\n    assert_eq(e, {exponent});",
                    tbs.len(),
                    n.len(),
                    bytes(n)
                )
            }
            PublicKey::Ec {
                curve: Some(c),
                point,
            } => {
                let dc = curves::der_curve(c.name())?;
                let (x, y) = point.get(1..).context("point")?.split_at(dc.s);
                format!(
                    "    let (x, y) = spki_ec({up}_TBS, f.spki_offset, f.len, curves::{});\n    assert_eq(x, {});\n    assert_eq(y, {});",
                    curves::der_global(c.name())?,
                    bytes(x),
                    bytes(y)
                )
            }
            PublicKey::Ec { curve: None, .. } => bail!("{name}: key on an unknown curve"),
        };
        writeln!(
            out,
            "#[test]\nfn {name}_key() {{\n    let f = parse_tbs({up}_TBS);\n{check}\n}}\n"
        )?;
    }
    Ok(out)
}

/// Writes `fresh` to `path`, or with `check` fails if the file differs from
/// it modulo `nargo fmt` reflow (whitespace, trailing commas).
fn write_or_check(path: &Path, fresh: &str, check: bool) -> Result<()> {
    if !check {
        std::fs::write(path, fresh)?;
        return Ok(());
    }
    let squash = |s: &str| {
        s.split_whitespace()
            .collect::<String>()
            .replace(",]", "]")
            .replace(",}", "}")
            .replace(",)", ")")
    };
    let current = std::fs::read_to_string(path).unwrap_or_default();
    ensure!(
        squash(&current) == squash(fresh),
        "{} is stale; rerun without --check",
        path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every generated Noir file matches what the fixtures produce today.
    #[test]
    fn generated_files_are_current() {
        write_or_check(
            &root().join("noir/lib/rsa/src/vectors.nr"),
            &rsa().unwrap(),
            true,
        )
        .unwrap();
        write_or_check(
            &root().join("noir/lib/ecdsa/src/vectors.nr"),
            &ecdsa().unwrap(),
            true,
        )
        .unwrap();
        write_or_check(
            &root().join("noir/lib/der/src/vectors.nr"),
            &der_vectors().unwrap(),
            true,
        )
        .unwrap();
        write_or_check(
            &root().join("noir/lib/steps/src/vectors.nr"),
            &steps::steps_vectors().unwrap(),
            true,
        )
        .unwrap();
        for (rel, contents) in circuits::files().unwrap() {
            write_or_check(&root().join(rel), &contents, true).unwrap();
        }
        write_or_check(
            &root().join("docs/COSTS.md"),
            &costs::report().unwrap(),
            true,
        )
        .unwrap();
        for (name, prefix, strukt) in curves::GENERATED {
            let path = root().join(format!(
                "noir/vendor/noir_bigcurve/src/curves/eid_{prefix}.nr"
            ));
            write_or_check(&path, &curves::module(name, prefix, strukt).unwrap(), true).unwrap();
        }
    }

    #[test]
    fn check_mode_detects_drift() {
        let dir = std::env::temp_dir().join(format!("eid-vectors-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("x.nr");
        std::fs::write(&file, "global A: [u8; 2] = [\n    1,\n    2,\n];\n").unwrap();
        assert!(write_or_check(&file, "global A: [u8; 2] = [1, 2];", true).is_ok());
        assert!(write_or_check(&file, "global A: [u8; 2] = [1, 3];", true).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn limbs_are_little_endian_120_bit() {
        let x = (BigUint::from(5u8) << 120u32) + 7u8;
        assert_eq!(limbs(&x, 2), "[0x7, 0x5]");
        assert_eq!(left_pad(&[0, 0, 1], 3).unwrap(), vec![0, 0, 1]);
        assert!(left_pad(&[1, 2, 3], 2).is_err());
    }
}
