//! Synthetic eMRTD documents for the SOD and envelope steps.
//!
//! Real SODs are personal data, so the step B and C vectors are built here:
//! a DSC `TBSCertificate` with a key of the configuration under test, an LDS
//! security object over mock DG1 (ICAO 9303 specimen MRZ) and DG11, and
//! signed attributes carrying its digest, signed with the DSC key. Every
//! signature is re-verified with csca-registry's RustCrypto verifier before
//! it is emitted. Keys are deterministic (seeded), so the output is stable.

use crate::curves::{curve, der_curve, oid_tlv};
use anyhow::{bail, ensure, Context, Result};
use csca_registry::crypto::{self, Hash, PublicKey, Scheme};
use eid_prover::config::Config;
use num_bigint::BigUint;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rsa::traits::PublicKeyParts;
use rsa::{Pkcs1v15Sign, Pss, RsaPrivateKey};
use sha2::{Digest, Sha256};
use std::collections::btree_map::{BTreeMap, Entry};
use std::sync::Mutex;

/// DER TLV with a definite length.
pub(crate) fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let len = content.len();
    let mut out = vec![tag];
    match len {
        0..=0x7f => out.push(u8::try_from(len).unwrap_or(0)),
        0x80..=0xff => out.extend([0x81, u8::try_from(len).unwrap_or(0)]),
        _ => {
            out.push(0x82);
            out.extend(u16::try_from(len).unwrap_or(u16::MAX).to_be_bytes());
        }
    }
    out.extend_from_slice(content);
    out
}

fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

/// DER SET OF: elements sorted by their encodings (X.690 §11.6).
fn set_of(mut parts: Vec<Vec<u8>>) -> Vec<u8> {
    parts.sort();
    tlv(0x31, &parts.concat())
}

fn oid(dotted: &str) -> Vec<u8> {
    oid_tlv(dotted).unwrap_or_default()
}

/// Minimal non-negative DER INTEGER.
fn uint(be: &[u8]) -> Vec<u8> {
    let first = be.iter().position(|b| *b != 0).unwrap_or(be.len());
    let mut v = be[first..].to_vec();
    if v.is_empty() || v[0] >= 0x80 {
        v.insert(0, 0);
    }
    tlv(0x02, &v)
}

fn hash_oid(h: Hash) -> &'static str {
    match h {
        Hash::Sha1 => "1.3.14.3.2.26",
        Hash::Sha224 => "2.16.840.1.101.3.4.2.4",
        Hash::Sha256 => "2.16.840.1.101.3.4.2.1",
        Hash::Sha384 => "2.16.840.1.101.3.4.2.2",
        Hash::Sha512 => "2.16.840.1.101.3.4.2.3",
    }
}

/// `DigestInfo ::= SEQUENCE { AlgorithmIdentifier, OCTET STRING digest }`
/// without the digest bytes.
fn digest_info(h: Hash) -> Vec<u8> {
    let len = h.digest(b"").len();
    let full = seq(&[
        seq(&[oid(hash_oid(h)), vec![0x05, 0x00]]),
        tlv(0x04, &vec![0; len]),
    ]);
    full[..full.len() - len].to_vec()
}

/// A DSC private key.
pub(crate) enum Key {
    Rsa(Box<RsaPrivateKey>),
    Ec {
        name: &'static str,
        d: BigUint,
        q: (BigUint, BigUint),
    },
}

fn seed(label: &str) -> [u8; 32] {
    Sha256::digest(format!("eid-circuits mock key {label}").as_bytes()).into()
}

/// The configuration's curve name as csca-registry spells it.
fn curve_name(label: &str) -> Result<&'static str> {
    Ok(match label {
        "p256" => "P-256",
        "p384" => "P-384",
        "p521" => "P-521",
        "bp256" => "brainpoolP256r1",
        "bp384" => "brainpoolP384r1",
        "bp512" => "brainpoolP512r1",
        other => bail!("unknown curve {other}"),
    })
}

impl Key {
    /// Deterministic DSC key for `config`.
    pub(crate) fn for_config(config: Config) -> Result<Self> {
        Self::for_role(config, "")
    }

    /// Deterministic key for `config` in `role` ("" for DSCs, "csca" for the
    /// mock CSCA): different roles get unrelated keys.
    pub(crate) fn for_role(config: Config, role: &str) -> Result<Self> {
        let label = |base: &str| {
            if role.is_empty() {
                base.to_string()
            } else {
                format!("{role} {base}")
            }
        };
        match config {
            Config::Pkcs1 { bits, .. } | Config::Pss { bits, .. } => {
                static CACHE: Mutex<BTreeMap<String, RsaPrivateKey>> = Mutex::new(BTreeMap::new());
                let mut cache = CACHE
                    .lock()
                    .map_err(|_| anyhow::anyhow!("key cache poisoned"))?;
                let key = match cache.entry(label(&format!("rsa-{bits}"))) {
                    Entry::Occupied(e) => e.get().clone(),
                    Entry::Vacant(v) => {
                        let mut rng = ChaCha20Rng::from_seed(seed(v.key()));
                        v.insert(RsaPrivateKey::new(&mut rng, usize::try_from(bits)?)?)
                            .clone()
                    }
                };
                Ok(Self::Rsa(Box::new(key)))
            }
            Config::Ecdsa {
                curve: curve_id, ..
            } => {
                let name = curve_name(curve_id)?;
                let c = curve(name)?;
                let d = BigUint::from_bytes_be(&seed(&label(name))) % (&c.n - 1u8) + 1u8;
                let q = c
                    .mul(&d, &Some(c.g.clone()))
                    .context("public key is infinity")?;
                Ok(Self::Ec { name, d, q })
            }
        }
    }

    /// The key as csca-registry represents it.
    pub(crate) fn public(&self) -> Result<PublicKey> {
        Ok(match self {
            Self::Rsa(k) => PublicKey::Rsa {
                n: k.n().to_bytes_be(),
                e: k.e().to_bytes_be(),
            },
            Self::Ec { name, q, .. } => {
                let s = der_curve(name)?.s;
                PublicKey::Ec {
                    curve: crypto::Curve::from_oid(&oid_str(name)?),
                    point: [vec![4], fixed(&q.0, s), fixed(&q.1, s)].concat(),
                }
            }
        })
    }

    /// `SubjectPublicKeyInfo`. RSA-PSS keys use id-RSASSA-PSS, other RSA keys
    /// rsaEncryption; P-256 uses its named-curve OID and the other curves
    /// explicit `ECParameters`, as ICAO 9303 asks for.
    fn spki(&self, config: Config) -> Result<Vec<u8>> {
        Ok(match self {
            Self::Rsa(k) => {
                let alg = if matches!(config, Config::Pss { .. }) {
                    seq(&[oid("1.2.840.113549.1.1.10"), seq(&[])])
                } else {
                    seq(&[oid("1.2.840.113549.1.1.1"), vec![0x05, 0x00]])
                };
                let key = seq(&[uint(&k.n().to_bytes_be()), uint(&k.e().to_bytes_be())]);
                seq(&[alg, tlv(0x03, &[vec![0], key].concat())])
            }
            Self::Ec { name, q, .. } => {
                let dc = der_curve(name)?;
                let c = curve(name)?;
                let params = if *name == "P-256" {
                    dc.oid.clone()
                } else {
                    seq(&[
                        uint(&[1]),
                        seq(&[oid("1.2.840.10045.1.1"), uint(&dc.p)]),
                        seq(&[tlv(0x04, &dc.a), tlv(0x04, &dc.b)]),
                        tlv(
                            0x04,
                            &[vec![4], fixed(&c.g.0, dc.s), fixed(&c.g.1, dc.s)].concat(),
                        ),
                        uint(&c.n.to_bytes_be()),
                        uint(&[1]),
                    ])
                };
                let alg = seq(&[oid("1.2.840.10045.2.1"), params]);
                let point = [vec![0, 4], fixed(&q.0, dc.s), fixed(&q.1, dc.s)].concat();
                seq(&[alg, tlv(0x03, &point)])
            }
        })
    }

    /// Signs `msg` under `config`: the raw RSA signature (modulus size), or
    /// `r ‖ s` for ECDSA, each the coordinate size.
    pub(crate) fn sign(&self, config: Config, msg: &[u8]) -> Result<Vec<u8>> {
        match (self, config) {
            (Self::Rsa(k), Config::Pkcs1 { hash, .. }) => {
                let payload = [digest_info(hash), hash.digest(msg)].concat();
                Ok(k.sign(Pkcs1v15Sign::new_unprefixed(), &payload)?)
            }
            (Self::Rsa(k), Config::Pss { hash, salt, .. }) => {
                let mut rng = ChaCha20Rng::from_seed(seed("pss salt"));
                let digest = hash.digest(msg);
                Ok(match hash {
                    Hash::Sha1 => {
                        k.sign_with_rng(&mut rng, Pss::new_with_salt::<sha1::Sha1>(salt), &digest)?
                    }
                    Hash::Sha224 => k.sign_with_rng(
                        &mut rng,
                        Pss::new_with_salt::<sha2::Sha224>(salt),
                        &digest,
                    )?,
                    Hash::Sha256 => k.sign_with_rng(
                        &mut rng,
                        Pss::new_with_salt::<sha2::Sha256>(salt),
                        &digest,
                    )?,
                    Hash::Sha384 => k.sign_with_rng(
                        &mut rng,
                        Pss::new_with_salt::<sha2::Sha384>(salt),
                        &digest,
                    )?,
                    Hash::Sha512 => k.sign_with_rng(
                        &mut rng,
                        Pss::new_with_salt::<sha2::Sha512>(salt),
                        &digest,
                    )?,
                })
            }
            (Self::Ec { name, d, .. }, Config::Ecdsa { hash, .. }) => {
                let c = curve(name)?;
                let digest = hash.digest(msg);
                // bits2int: the leftmost bits of the digest, as many as n has.
                let mut e = BigUint::from_bytes_be(&digest);
                let (hb, nb) = (8 * digest.len() as u64, c.n.bits());
                if hb > nb {
                    e >>= hb - nb;
                }
                // Deterministic nonce for test vectors only.
                let k = BigUint::from_bytes_be(&Sha256::digest(
                    [d.to_bytes_be(), digest.clone()].concat(),
                )) % (&c.n - 1u8)
                    + 1u8;
                let (rx, _) = c.mul(&k, &Some(c.g.clone())).context("kG is infinity")?;
                let r = rx % &c.n;
                let k_inv = k.modpow(&(&c.n - 2u8), &c.n);
                let s = (k_inv * (e + &r * d)) % &c.n;
                ensure!(
                    r != BigUint::ZERO && s != BigUint::ZERO,
                    "degenerate signature"
                );
                let s_len = der_curve(name)?.s;
                Ok([fixed(&r, s_len), fixed(&s, s_len)].concat())
            }
            _ => bail!("key does not match {config:?}"),
        }
    }
}

fn oid_str(name: &str) -> Result<String> {
    crate::curve_params::CURVES
        .iter()
        .find(|r| r.0 == name)
        .map(|r| r.1.to_string())
        .with_context(|| format!("no curve {name}"))
}

/// `v` big-endian in exactly `n` bytes.
pub(crate) fn fixed(v: &BigUint, n: usize) -> Vec<u8> {
    let b = v.to_bytes_be();
    let mut o = vec![0u8; n.saturating_sub(b.len())];
    o.extend(b);
    o
}

/// The csca-registry scheme for `config`.
pub(crate) fn scheme(config: Config) -> Scheme {
    match config {
        Config::Pkcs1 { hash, .. } => Scheme::RsaPkcs1(hash),
        Config::Pss { hash, salt, .. } => Scheme::RsaPss {
            hash,
            mgf: hash,
            salt,
        },
        Config::Ecdsa { hash, .. } => Scheme::Ecdsa { hash, plain: false },
    }
}

/// ICAO 9303 check digit (weights 7, 3, 1).
fn check_digit(s: &str) -> char {
    let sum: u32 = s
        .bytes()
        .enumerate()
        .map(|(i, c)| {
            let v = match c {
                b'0'..=b'9' => u32::from(c - b'0'),
                b'A'..=b'Z' => u32::from(c - b'A') + 10,
                _ => 0,
            };
            v * [7, 3, 1][i % 3]
        })
        .sum();
    char::from(b'0' + u8::try_from(sum % 10).unwrap_or(0))
}

/// TD3 (passport) MRZ for the ICAO 9303 specimen, with `expiry` as YYMMDD.
pub(crate) fn td3_mrz(country: &str, expiry: &str) -> String {
    let line1 = format!("P<{country}ERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<");
    let number = "L898902C3";
    let birth = "740812";
    let optional = "ZE184226B<<<<<";
    let (n, b, e, o) = (
        format!("{number}{}", check_digit(number)),
        format!("{birth}{}", check_digit(birth)),
        format!("{expiry}{}", check_digit(expiry)),
        format!("{optional}{}", check_digit(optional)),
    );
    let composite = check_digit(&format!("{n}{b}{e}{o}"));
    format!("{line1}{n}{country}{b}F{e}{o}{composite}")
}

/// TD1 (ID card, 3 × 30) MRZ for the ICAO 9303 specimen.
pub(crate) fn td1_mrz(country: &str, expiry: &str) -> String {
    let number = "D23145890";
    let line1 = format!("I<{country}{number}{}<<<<<<<<<<<<<<<", check_digit(number));
    let (birth, e) = (
        format!("740812{}", check_digit("740812")),
        format!("{expiry}{}", check_digit(expiry)),
    );
    let upper = format!("{}{birth}{e}<<<<<<<<<<<", &line1[5..30]);
    let line2 = format!("{birth}F{e}{country}<<<<<<<<<<<{}", check_digit(&upper));
    format!("{line1}{line2}ERIKSSON<<ANNA<MARIA<<<<<<<<<<")
}

/// TD2 (2 × 36) MRZ for the ICAO 9303 specimen.
pub(crate) fn td2_mrz(country: &str, expiry: &str) -> String {
    let number = "D23145890";
    let (n, b, e) = (
        format!("{number}{}", check_digit(number)),
        format!("740812{}", check_digit("740812")),
        format!("{expiry}{}", check_digit(expiry)),
    );
    let composite = check_digit(&format!("{n}{b}{e}<<<<<<<"));
    format!("I<{country}ERIKSSON<<ANNA<MARIA<<<<<<<<<<<{n}{country}{b}F{e}<<<<<<<{composite}")
}

/// DG1 for an MRZ: `61 L 5F1F L' MRZ`.
pub(crate) fn dg1(mrz: &str) -> Vec<u8> {
    tlv(0x61, &tlv_2(0x5f1f, mrz.as_bytes()))
}

/// A mock CSCA: a self-signed certificate under `config` for `country`
/// (alpha-2), to be loaded into a test registry.
pub(crate) struct Csca {
    pub config: Config,
    pub key: Key,
    pub country: String,
    pub cert: Vec<u8>,
}

impl Csca {
    pub(crate) fn new(config: Config, country: &str) -> Result<Self> {
        let key = Key::for_role(config, "csca")?;
        let subject = dn(country, "Mock CSCA");
        // basicConstraints (critical, CA) and keyUsage (critical, keyCertSign | cRLSign).
        let extensions = tlv(
            0xa3,
            &seq(&[
                seq(&[
                    oid("2.5.29.19"),
                    vec![0x01, 0x01, 0xff],
                    tlv(0x04, &seq(&[vec![0x01, 0x01, 0xff]])),
                ]),
                seq(&[
                    oid("2.5.29.15"),
                    vec![0x01, 0x01, 0xff],
                    tlv(0x04, &[0x03, 0x02, 0x01, 0x06]),
                ]),
            ]),
        );
        let tbs = seq(&[
            tlv(0xa0, &uint(&[2])),
            uint(&Sha256::digest(format!("csca {}", config.label()).as_bytes())[..8]),
            signature_alg(config),
            subject.clone(),
            seq(&[tlv(0x17, b"200101000000Z"), tlv(0x18, b"20400101000000Z")]),
            subject,
            key.spki(config)?,
            extensions,
        ]);
        let cert = certificate(tbs, config, &key)?;
        Ok(Self {
            config,
            key,
            country: country.to_string(),
            cert,
        })
    }
}

/// `SEQUENCE { SET { C=country }, SET { CN=cn } }`.
fn dn(country: &str, cn: &str) -> Vec<u8> {
    seq(&[
        set_of(vec![seq(&[oid("2.5.4.6"), tlv(0x13, country.as_bytes())])]),
        set_of(vec![seq(&[oid("2.5.4.3"), tlv(0x13, cn.as_bytes())])]),
    ])
}

/// The AlgorithmIdentifier of a signature under `config`, as certificates
/// and SignerInfos write it.
pub(crate) fn signature_alg(config: Config) -> Vec<u8> {
    let hash_alg = |h: Hash| seq(&[oid(hash_oid(h)), vec![0x05, 0x00]]);
    match config {
        Config::Pkcs1 { hash, .. } => {
            let o = match hash {
                Hash::Sha1 => "1.2.840.113549.1.1.5",
                Hash::Sha224 => "1.2.840.113549.1.1.14",
                Hash::Sha256 => "1.2.840.113549.1.1.11",
                Hash::Sha384 => "1.2.840.113549.1.1.12",
                Hash::Sha512 => "1.2.840.113549.1.1.13",
            };
            seq(&[oid(o), vec![0x05, 0x00]])
        }
        Config::Pss { hash, salt, .. } => {
            let salt = u32::try_from(salt).unwrap_or(0).to_be_bytes();
            seq(&[
                oid("1.2.840.113549.1.1.10"),
                seq(&[
                    tlv(0xa0, &hash_alg(hash)),
                    tlv(0xa1, &seq(&[oid("1.2.840.113549.1.1.8"), hash_alg(hash)])),
                    tlv(0xa2, &uint(&salt)),
                ]),
            ])
        }
        Config::Ecdsa { hash, .. } => {
            let o = match hash {
                Hash::Sha1 => "1.2.840.10045.4.1",
                Hash::Sha224 => "1.2.840.10045.4.3.1",
                Hash::Sha256 => "1.2.840.10045.4.3.2",
                Hash::Sha384 => "1.2.840.10045.4.3.3",
                Hash::Sha512 => "1.2.840.10045.4.3.4",
            };
            seq(&[oid(o)])
        }
    }
}

/// `SEQUENCE { tbs, signatureAlgorithm, BIT STRING signature }`.
fn certificate(tbs: Vec<u8>, config: Config, signer: &Key) -> Result<Vec<u8>> {
    let raw = signer.sign(config, &tbs)?;
    let sig = match config {
        Config::Ecdsa { .. } => {
            let (r, s) = raw.split_at(raw.len() / 2);
            seq(&[uint(r), uint(s)])
        }
        _ => raw,
    };
    Ok(seq(&[
        tbs,
        signature_alg(config),
        tlv(0x03, &[vec![0], sig].concat()),
    ]))
}

/// A synthetic document signed under `config`.
pub(crate) struct Doc {
    /// DSC `TBSCertificate` (its CSCA signature is out of scope for step B).
    pub tbs: Vec<u8>,
    /// The signed DSC certificate and the EF.SOD (only for [`Doc::issued`]).
    pub dsc_cert: Vec<u8>,
    pub ef_sod: Vec<u8>,
    /// DSC public key.
    pub dsc_key: PublicKey,
    /// signedAttrs in signed form (tag 0x31).
    pub attrs: Vec<u8>,
    /// Offset of the messageDigest attribute in `attrs`.
    pub md_offset: usize,
    /// DSC signature over `attrs`: raw RSA, or `r ‖ s`.
    pub signature: Vec<u8>,
    /// eContent: the LDS security object.
    pub econtent: Vec<u8>,
    /// Hash of `econtent` in messageDigest.
    pub md_hash: Hash,
    /// Offset of the DG1 entry in `econtent`.
    pub dg1_offset: usize,
    pub dg1: Vec<u8>,
}

/// How a synthetic document's security object is built.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Lds {
    /// Hash of the eContent (messageDigest).
    pub md_hash: Hash,
    /// Hash of the data groups.
    pub dg_hash: Hash,
    /// LDS 1.8 (version 1, with ldsVersionInfo) instead of version 0.
    pub v1: bool,
    /// Whether the LDS lists a DG11 (the circuits ignore it).
    pub with_dg11: bool,
}

impl Doc {
    /// Builds and self-verifies a document. `country` is the issuing state
    /// (three letters) and `expiry` the MRZ date of expiry (YYMMDD).
    pub(crate) fn new(config: Config, country: &str, expiry: &str) -> Result<Self> {
        let hash = match config {
            Config::Pkcs1 { hash, .. } | Config::Pss { hash, .. } | Config::Ecdsa { hash, .. } => {
                hash
            }
        };
        let lds = Lds {
            md_hash: hash,
            dg_hash: hash,
            v1: false,
            with_dg11: true,
        };
        Self::build(config, lds, country, expiry)
    }

    /// [`Doc::new`] with the security object described by `lds`.
    pub(crate) fn build(config: Config, lds: Lds, country: &str, expiry: &str) -> Result<Self> {
        Self::build_with(config, lds, country, expiry, None)
    }

    /// A complete document: the DSC certificate is signed by `csca` and the
    /// SOD is a full EF.SOD (ICAO 9303 part 10: CMS SignedData with the DSC).
    /// `mrz_state` is the MRZ issuing state (e.g. `D<<`).
    pub(crate) fn issued(
        csca: &Csca,
        config: Config,
        lds: Lds,
        mrz_state: &str,
        expiry: &str,
    ) -> Result<Self> {
        Self::build_with(config, lds, mrz_state, expiry, Some(csca))
    }

    fn build_with(
        config: Config,
        lds: Lds,
        country: &str,
        expiry: &str,
        csca: Option<&Csca>,
    ) -> Result<Self> {
        let key = Key::for_config(config)?;
        let dsc_key = key.public()?;

        let mrz = td3_mrz(country, expiry);
        let dg1 = dg1(&mrz);
        let dg11 = tlv(
            0x6b,
            &[
                tlv(0x5c, &[0x5f, 0x0e, 0x5f, 0x11]),
                tlv_2(0x5f0e, b"ERIKSSON<<ANNA<MARIA"),
                tlv_2(0x5f11, b"ZENITH"),
            ]
            .concat(),
        );
        let dg2 = tlv(0x75, b"mock face image");
        let dg14 = tlv(0x6e, b"mock security infos");
        let entry = |n: u8, dg: &[u8]| seq(&[uint(&[n]), tlv(0x04, &lds.dg_hash.digest(dg))]);
        let mut entries = vec![entry(1, &dg1), entry(2, &dg2)];
        if lds.with_dg11 {
            entries.push(entry(11, &dg11));
        }
        entries.push(entry(14, &dg14));
        let mut parts = vec![
            uint(&[u8::from(lds.v1)]),
            // v1 documents write the NULL parameter, v0 ones omit it.
            if lds.v1 {
                seq(&[oid(hash_oid(lds.dg_hash)), vec![0x05, 0x00]])
            } else {
                seq(&[oid(hash_oid(lds.dg_hash))])
            },
            seq(&entries),
        ];
        if lds.v1 {
            parts.push(seq(&[tlv(0x13, b"0108"), tlv(0x13, b"040000")]));
        }
        let econtent = seq(&parts);
        let find = |needle: &[u8]| (0..econtent.len()).find(|&i| econtent[i..].starts_with(needle));
        let dg1_offset = find(&entry(1, &dg1)).context("DG1 entry")?;

        let md_attr = seq(&[
            oid("1.2.840.113549.1.9.4"),
            set_of(vec![tlv(0x04, &lds.md_hash.digest(&econtent))]),
        ]);
        let attrs = set_of(vec![
            seq(&[
                oid("1.2.840.113549.1.9.3"),
                set_of(vec![oid("2.23.136.1.1.1")]),
            ]),
            seq(&[
                oid("1.2.840.113549.1.9.5"),
                set_of(vec![tlv(0x17, b"260101120000Z")]),
            ]),
            md_attr.clone(),
        ]);
        let md_offset = (0..attrs.len())
            .find(|&i| attrs[i..].starts_with(&md_attr))
            .context("messageDigest attribute")?;

        let name = |cn: &str| {
            seq(&[
                set_of(vec![seq(&[oid("2.5.4.6"), tlv(0x13, b"UT")])]),
                set_of(vec![seq(&[oid("2.5.4.3"), tlv(0x13, cn.as_bytes())])]),
            ])
        };
        let serial = uint(&Sha256::digest(config.label().as_bytes())[..8]);
        let (sig_alg, issuer, subject) = match csca {
            Some(c) => (
                signature_alg(c.config),
                dn(&c.country, "Mock CSCA"),
                dn(&c.country, "Mock DSC"),
            ),
            None => (
                seq(&[oid("1.2.840.113549.1.1.11"), vec![0x05, 0x00]]),
                name("Mock CSCA"),
                name("Mock DSC"),
            ),
        };
        let tbs = seq(&[
            tlv(0xa0, &uint(&[2])),
            serial.clone(),
            sig_alg,
            issuer.clone(),
            seq(&[tlv(0x17, b"250101000000Z"), tlv(0x17, b"350101000000Z")]),
            subject,
            key.spki(config)?,
        ]);
        ensure!(
            PublicKey::from_spki(&key.spki(config)?)?.material() == dsc_key.material(),
            "SPKI does not round-trip through csca-registry"
        );

        let signature = key.sign(config, &attrs)?;
        let der_sig = match config {
            Config::Ecdsa { .. } => {
                let (r, s) = signature.split_at(signature.len() / 2);
                seq(&[uint(r), uint(s)])
            }
            _ => signature.clone(),
        };
        crypto::verify(&scheme(config), &dsc_key, &attrs, &der_sig).map_err(|e| {
            anyhow::anyhow!("{}: mock signature does not verify: {e}", config.label())
        })?;

        let (dsc_cert, ef_sod) = match csca {
            None => (vec![], vec![]),
            Some(c) => {
                let cert = certificate(tbs.clone(), c.config, &c.key)?;
                let digest_alg = seq(&[oid(hash_oid(lds.md_hash)), vec![0x05, 0x00]]);
                // In the SignerInfo the attributes are [0] IMPLICIT, not a SET.
                let mut implicit = attrs.clone();
                implicit[0] = 0xa0;
                let signer_info = seq(&[
                    uint(&[1]),
                    seq(&[issuer.clone(), serial.clone()]),
                    digest_alg.clone(),
                    implicit,
                    signature_alg(config),
                    tlv(0x04, &der_sig),
                ]);
                let signed_data = seq(&[
                    uint(&[3]),
                    set_of(vec![digest_alg]),
                    seq(&[oid("2.23.136.1.1.1"), tlv(0xa0, &tlv(0x04, &econtent))]),
                    tlv(0xa0, &cert),
                    set_of(vec![signer_info]),
                ]);
                let content_info = seq(&[oid("1.2.840.113549.1.7.2"), tlv(0xa0, &signed_data)]);
                (cert, tlv(0x77, &content_info))
            }
        };

        Ok(Self {
            tbs,
            dsc_cert,
            ef_sod,
            dsc_key,
            attrs,
            md_offset,
            signature,
            econtent,
            md_hash: lds.md_hash,
            dg1_offset,
            dg1,
        })
    }
}

/// TLV with a two-byte tag (DG1 `5F1F`, DG11 `5F0E`, …).
fn tlv_2(tag: u16, content: &[u8]) -> Vec<u8> {
    let mut t = tlv(0, content);
    t[0] = (tag & 0xff) as u8;
    t.insert(0, (tag >> 8) as u8);
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn specimen_mrz_check_digits() {
        // ICAO 9303 part 4 specimen (expiry 120415).
        assert_eq!(
            td3_mrz("UTO", "120415"),
            "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10"
        );
    }

    #[test]
    fn mrz_formats() {
        assert_eq!(td1_mrz("UTO", "120415").len(), 90);
        assert_eq!(td2_mrz("UTO", "120415").len(), 72);
        // ICAO 9303 part 5/6 specimens.
        assert!(td1_mrz("UTO", "120415")
            .starts_with("I<UTOD231458907<<<<<<<<<<<<<<<7408122F1204159UTO"));
        assert_eq!(
            &td2_mrz("UTO", "120415")[36..],
            "D231458907UTO7408122F1204159<<<<<<<6"
        );
    }

    #[test]
    fn documents_verify_for_every_config() {
        for &c in eid_prover::config::DSC_CONFIGS {
            let d = Doc::new(c, "UTO", "340415").unwrap();
            assert_eq!(d.dg1.len(), 93);
            assert_eq!(d.attrs[d.md_offset], 0x30);
        }
    }
}
