//! Test-vector generator for eid-circuits.
//!
//! ```text
//! eid-vectors extract --sources <csca-registry>/tests/fixtures/sources   # refresh fixtures/*.der
//! eid-vectors rsa                                                         # write noir/lib/rsa/src/vectors.nr
//! eid-vectors rsa --check                                                 # fail if it is stale (CI)
//! ```
//!
//! Every vector is a real CSCA certificate from a master list, checked with
//! csca-registry's RustCrypto verifier before it is emitted.

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
const RSA_CASES: &[(&str, &str)] = &[
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
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Extract { sources } => extract(&sources),
        Command::Rsa { check } => {
            write_or_check(&root().join("noir/lib/rsa/src/vectors.nr"), &rsa()?, check)
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
    for (name, prefix) in RSA_CASES {
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

fn bytes(b: &[u8]) -> String {
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
