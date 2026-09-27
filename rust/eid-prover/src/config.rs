//! The circuit variants and how a document maps onto them.
//!
//! Every step circuit is generated per configuration (`eid-vectors
//! circuits`); this module names them, so the generator and the prover agree
//! on which circuit a document needs.

use csca_registry::cert::Cert;
use csca_registry::crypto::{Hash, PublicKey, Scheme};

/// A signing configuration: the signer's key and scheme. Used for both the
/// CSCA signing a DSC (step A) and the DSC signing the SOD (step B).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Config {
    Pkcs1 { bits: u32, hash: Hash },
    Pss { bits: u32, hash: Hash, salt: usize },
    Ecdsa { curve: &'static str, hash: Hash },
}

/// Every (CSCA key, signature scheme) pair among verified signatures in the
/// DE + IT master lists (csca-registry fixtures), 2026-09-27.
pub const DSC_CONFIGS: &[Config] = &[
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

impl Config {
    /// Human-readable key and scheme, e.g. `RSA-4096 · PSS SHA-256 salt 32`.
    pub fn label(self) -> String {
        let up = |h: Hash| h.name().to_uppercase().replace("SHA", "SHA-");
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
            Config::Pkcs1 { bits, hash: h } => ("rsa_pkcs1v15", format!("{bits}_{}", h.name())),
            Config::Pss {
                bits,
                hash: h,
                salt,
            } => ("rsa_pss", format!("{bits}_{}_s{salt}", h.name())),
            Config::Ecdsa { curve, hash: h } => ("ecdsa", format!("{curve}_{}", h.name())),
        }
    }

    pub fn package(self, t: usize) -> String {
        self.step_package("dsc", t)
    }

    pub fn dir(self, t: usize) -> String {
        self.step_dir("dsc", t)
    }

    /// Package of this configuration's circuit in `step` (`dsc`, `sod`).
    pub fn step_package(self, step: &str, t: usize) -> String {
        let (g, v) = self.dirs();
        format!("{step}_{g}_{v}_tbs{t}")
    }

    pub fn step_dir(self, step: &str, t: usize) -> String {
        let (g, v) = self.dirs();
        format!("noir/circuits/{step}/{g}/{v}/tbs_{t}")
    }

    /// The configuration's hash.
    pub fn hash(self) -> Hash {
        match self {
            Config::Pkcs1 { hash, .. } | Config::Pss { hash, .. } | Config::Ecdsa { hash, .. } => {
                hash
            }
        }
    }

    /// The configuration a certificate was signed with, if generated.
    pub fn of(cert: &Cert, issuer_key: &PublicKey) -> Option<Self> {
        Self::from_scheme(&cert.scheme.clone().ok()?, issuer_key)
    }

    /// The configuration for `scheme` under `key`, if a circuit exists for it.
    pub fn from_scheme(scheme: &Scheme, key: &PublicKey) -> Option<Self> {
        let found = match (*scheme, key) {
            (Scheme::RsaPkcs1(h), PublicKey::Rsa { .. }) => Config::Pkcs1 {
                bits: u32::try_from(key.bits()).ok()?,
                hash: h,
            },
            (Scheme::RsaPss { hash: h, mgf, salt }, PublicKey::Rsa { .. }) if mgf == h => {
                Config::Pss {
                    bits: u32::try_from(key.bits()).ok()?,
                    hash: h,
                    salt,
                }
            }
            (
                Scheme::Ecdsa {
                    hash: h,
                    plain: false,
                },
                PublicKey::Ec { curve: Some(c), .. },
            ) => Config::Ecdsa {
                curve: curve_label(c.name())?,
                hash: h,
            },
            _ => return None,
        };
        DSC_CONFIGS.contains(&found).then_some(found)
    }
}

/// The circuits' curve label for a csca-registry curve name.
pub fn curve_label(name: &str) -> Option<&'static str> {
    Some(match name {
        "P-256" => "p256",
        "P-384" => "p384",
        "P-521" => "p521",
        "brainpoolP256r1" => "bp256",
        "brainpoolP384r1" => "bp384",
        "brainpoolP512r1" => "bp512",
        _ => return None,
    })
}

/// TBSCertificate size buckets of the DSC and SOD steps.
pub const BUCKETS: [usize; 4] = [700, 1000, 1200, 1600];

/// The smallest TBSCertificate bucket that fits `len` bytes.
pub fn bucket(len: usize) -> Option<usize> {
    BUCKETS.into_iter().find(|b| *b >= len)
}

/// Hashes an LDS security object and its data groups use: every pair
/// (eContent hash, data group hash) gets a circuit per eContent bucket.
pub const LDS_HASHES: [Hash; 4] = [Hash::Sha1, Hash::Sha256, Hash::Sha384, Hash::Sha512];

/// eContent size buckets: 16 data groups with SHA-512 hashes take about 1.2 kB.
pub const LDS_BUCKETS: [usize; 3] = [512, 1024, 1536];

pub fn envelope_package(md: Hash, dg: Hash, e: usize) -> String {
    format!("envelope_{}_{}_lds{e}", md.name(), dg.name())
}

pub fn envelope_dir(md: Hash, dg: Hash, e: usize) -> String {
    format!("noir/circuits/envelope/{}_{}/lds_{e}", md.name(), dg.name())
}

/// The smallest eContent bucket that fits `len` bytes.
pub fn lds_bucket(len: usize) -> Option<usize> {
    LDS_BUCKETS.into_iter().find(|b| *b >= len)
}

/// The hash a signature scheme digests with.
pub fn scheme_hash(s: &Scheme) -> Hash {
    match *s {
        Scheme::RsaPkcs1(h) | Scheme::RsaPss { hash: h, .. } | Scheme::Ecdsa { hash: h, .. } => h,
    }
}
