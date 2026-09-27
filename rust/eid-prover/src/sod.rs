//! EF.SOD (ICAO 9303 part 10 §4.6.2): a CMS SignedData over the LDS security
//! object, carrying the DSC certificate that signed it.

use anyhow::{bail, ensure, Context, Result};
use csca_registry::cert::Cert;
use csca_registry::crypto::{Hash, Scheme};
use csca_registry::der::{self, Tlv};

const OID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
const OID_LDS_SECURITY_OBJECT: &str = "2.23.136.1.1.1";
const OID_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";

/// The parts of an EF.SOD the prover needs.
#[derive(Debug, Clone)]
pub struct Sod {
    /// The DSC certificate (the first certificate in the SignedData).
    pub dsc: Cert,
    /// The SignerInfo's signed attributes in the form that is signed: a DER SET.
    pub signed_attrs: Vec<u8>,
    /// Offset of the messageDigest attribute in `signed_attrs`.
    pub md_offset: usize,
    /// The messageDigest value.
    pub message_digest: Vec<u8>,
    /// SignerInfo digestAlgorithm: the eContent hash.
    pub digest: Hash,
    /// SignerInfo signature scheme and value (ECDSA: DER `SEQUENCE { r, s }`).
    pub scheme: Scheme,
    pub signature: Vec<u8>,
    /// The eContent: the LDS security object.
    pub econtent: Vec<u8>,
}

fn children<'a>(t: &Tlv<'a>, what: &str) -> Result<Vec<Tlv<'a>>> {
    der::children(t.content).with_context(|| format!("malformed {what}"))
}

fn hash_of(alg: &Tlv<'_>, what: &str) -> Result<Hash> {
    let (oid, _) = der::algorithm(alg.content).with_context(|| format!("malformed {what}"))?;
    Hash::from_oid(&oid).with_context(|| format!("unsupported {what} {oid}"))
}

impl Sod {
    /// Parses EF.SOD: `77 { ContentInfo { signedData, [0] SignedData } }`.
    pub fn parse(ef_sod: &[u8]) -> Result<Self> {
        let (app, _) = der::expect(ef_sod, 0x77).context("EF.SOD must start with tag 77")?;
        let (ci, _) = der::expect(app.content, 0x30).context("malformed ContentInfo")?;
        let ci = children(&ci, "ContentInfo")?;
        let [ct, content] = ci.as_slice() else {
            bail!("malformed ContentInfo")
        };
        ensure!(
            der::oid(ct.content).as_deref() == Some(OID_SIGNED_DATA),
            "not a SignedData"
        );
        let (sd, _) = der::expect(content.content, 0x30).context("malformed SignedData")?;
        let sd = children(&sd, "SignedData")?;

        // version, digestAlgorithms, encapContentInfo, [0] certificates, [1] crls, signerInfos
        let encap = sd.get(2).context("SignedData has no encapContentInfo")?;
        let encap = children(encap, "encapContentInfo")?;
        ensure!(
            encap.first().and_then(|t| der::oid(t.content)).as_deref()
                == Some(OID_LDS_SECURITY_OBJECT),
            "eContent is not an LDS security object"
        );
        let wrapped = encap.get(1).context("encapContentInfo has no eContent")?;
        let (econtent, _) = der::expect(wrapped.content, 0x04).context("malformed eContent")?;

        let certs = sd
            .iter()
            .find(|t| t.tag == 0xa0)
            .context("EF.SOD carries no DSC certificate")?;
        let (dsc, _) = der::read(certs.content).context("malformed certificate set")?;
        let dsc = Cert::from_der(dsc.raw).context("DSC certificate")?;

        let infos = sd
            .last()
            .filter(|t| t.tag == 0x31)
            .context("no signerInfos")?;
        let infos = children(infos, "signerInfos")?;
        ensure!(
            infos.len() == 1,
            "expected one SignerInfo, found {}",
            infos.len()
        );
        let si = children(&infos[0], "SignerInfo")?;
        // version, sid, digestAlgorithm, [0] signedAttrs, signatureAlgorithm, signature
        let [_, _, digest_alg, attrs, sig_alg, sig, ..] = si.as_slice() else {
            bail!("SignerInfo has no signed attributes")
        };
        ensure!(attrs.tag == 0xa0, "SignerInfo has no signed attributes");
        let digest = hash_of(digest_alg, "digestAlgorithm")?;
        let (oid, params) =
            der::algorithm(sig_alg.content).context("malformed signatureAlgorithm")?;
        let scheme = Scheme::from_algorithm(&oid, params, Some(digest))
            .map_err(|e| anyhow::anyhow!("SOD signature: {e}"))?;

        // The signed form of [0] IMPLICIT SET OF Attribute is the SET (RFC 5652 §5.4).
        let mut signed_attrs = attrs.raw.to_vec();
        signed_attrs[0] = 0x31;
        let (set, _) = der::read(&signed_attrs).context("malformed signed attributes")?;
        let header = signed_attrs.len() - set.content.len();
        let mut md = None;
        let mut offset = header;
        for a in children(&set, "signed attributes")? {
            let parts = children(&a, "attribute")?;
            if parts.first().and_then(|t| der::oid(t.content)).as_deref()
                == Some(OID_MESSAGE_DIGEST)
            {
                let values = children(
                    parts.get(1).context("messageDigest has no value")?,
                    "messageDigest",
                )?;
                let [value] = values.as_slice() else {
                    bail!("messageDigest must have one value")
                };
                ensure!(
                    value.tag == 0x04 && md.is_none(),
                    "malformed or repeated messageDigest"
                );
                md = Some((offset, value.content.to_vec()));
            }
            offset += a.raw.len();
        }
        let (md_offset, message_digest) = md.context("signed attributes have no messageDigest")?;

        Ok(Self {
            dsc,
            signed_attrs,
            md_offset,
            message_digest,
            digest,
            scheme,
            signature: sig.content.to_vec(),
            econtent: econtent.content.to_vec(),
        })
    }

    /// The LDS security object's data group hash algorithm and the hash it
    /// lists for data group `n`.
    pub fn data_group_hash(&self, n: u8) -> Result<(Hash, Vec<u8>)> {
        let (lds, _) =
            der::expect(&self.econtent, 0x30).context("malformed LDS security object")?;
        let f = der::children(lds.content).context("malformed LDS security object")?;
        let alg = f
            .get(1)
            .context("LDS security object has no hash algorithm")?;
        let hash = hash_of(alg, "LDS hash algorithm")?;
        let list = f
            .get(2)
            .context("LDS security object has no data group hashes")?;
        for e in der::children(list.content).context("malformed data group hashes")? {
            let p = der::children(e.content).context("malformed data group hash")?;
            if let [num, value] = p.as_slice() {
                if num.content == [n] {
                    return Ok((hash, value.content.to_vec()));
                }
            }
        }
        bail!("LDS security object doesn't list DG{n}")
    }
}
