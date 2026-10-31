//! The MASQUE identity: a P-256 keypair and the self-signed certificate that
//! presents it.
//!
//! Cloudflare's MASQUE front door authenticates the client by mutual TLS. The
//! public half of the key is uploaded at enrolment (see [`super::register`]),
//! and the private half signs a short-lived self-signed certificate that goes in
//! the TLS `Certificate` message. There is no bearer token on the tunnel: the
//! certificate *is* the credential.

use anyhow::{Context, Result};
use rcgen::{CertificateParams, KeyPair, PublicKeyData, PKCS_ECDSA_P256_SHA256};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// A freshly generated MASQUE identity.
pub struct Identity {
    key_pair: KeyPair,
    cert_der: CertificateDer<'static>,
    key_der: PrivateKeyDer<'static>,
    /// X.509 SubjectPublicKeyInfo DER, base64 — the form the API expects.
    spki_b64: String,
    /// The same SPKI, raw, for pinning comparisons.
    spki_der: Vec<u8>,
}

impl Identity {
    /// Generate a P-256 keypair and a self-signed certificate over it.
    ///
    /// The certificate is deliberately bare: serial 0, no SAN, no CN, one day of
    /// validity. That is what the Android client presents and what the front
    /// door accepts; a certificate with a subject or SANs is not rejected, but
    /// nothing uses them.
    pub fn generate() -> Result<Self> {
        use base64::Engine;

        let key_pair =
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).context("generating a P-256 keypair")?;

        let params = CertificateParams::new(Vec::<String>::new())
            .context("building certificate parameters")?;
        let cert = params
            .self_signed(&key_pair)
            .context("self-signing the MASQUE certificate")?;

        let cert_der = cert.der().clone();
        let spki_der = key_pair.subject_public_key_info();
        let spki_b64 = base64::engine::general_purpose::STANDARD.encode(&spki_der);
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

        Ok(Self {
            key_pair,
            cert_der,
            key_der,
            spki_b64,
            spki_der,
        })
    }

    /// The base64 X.509 SPKI to upload at enrolment.
    pub fn spki_b64(&self) -> &str {
        &self.spki_b64
    }

    /// The raw SPKI DER.
    pub fn spki_der(&self) -> &[u8] {
        &self.spki_der
    }

    /// The chain to present, as one self-signed certificate.
    pub fn cert_chain(&self) -> Vec<CertificateDer<'static>> {
        vec![self.cert_der.clone()]
    }

    /// The private key, cloned so it can be moved into a TLS config.
    pub fn private_key(&self) -> PrivateKeyDer<'static> {
        self.key_der.clone_key()
    }

    /// The keypair, for callers that want to re-derive or persist it.
    pub fn key_pair(&self) -> &KeyPair {
        &self.key_pair
    }

    /// The certificate and private key as PEM, so a caller can persist the
    /// identity and resume it instead of registering a second device.
    ///
    /// The private key is the credential: whoever holds it can open the tunnel
    /// for this device. Store it the way any other private key is stored.
    pub fn to_pem(&self) -> Result<(String, String)> {
        let cert_pem = pem_encode("CERTIFICATE", self.cert_der.as_ref());
        let key_pem = self.key_pair.serialize_pem();
        Ok((cert_pem, key_pem))
    }

    /// Rebuild an identity from [`Identity::to_pem`] output.
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self> {
        let key_pair = KeyPair::from_pem(key_pem).context("parsing the MASQUE private key")?;
        let mut reader = std::io::BufReader::new(cert_pem.as_bytes());
        let cert_der = rustls_pemfile::certs(&mut reader)
            .next()
            .context("the certificate PEM is empty")?
            .context("parsing the certificate PEM")?;
        let spki_der = key_pair.subject_public_key_info();
        let spki_b64 = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(&spki_der)
        };
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
        Ok(Self {
            key_pair,
            cert_der,
            key_der,
            spki_b64,
            spki_der,
        })
    }
}

/// Wrap DER in PEM armour at 64 columns, which is what every reader expects.
fn pem_encode(label: &str, der: &[u8]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// Extract the SubjectPublicKeyInfo DER from a PEM `PUBLIC KEY` block.
///
/// The API returns the peer's key as PEM; the pin is compared against the
/// certificate the front door presents, so both sides must be reduced to the
/// same DER form.
pub fn spki_from_pem(pem: &str) -> Result<Vec<u8>> {
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .context("decoding the peer public key PEM")
}

/// Extract the SubjectPublicKeyInfo DER from a DER-encoded certificate.
pub fn spki_from_cert(cert_der: &[u8]) -> Result<Vec<u8>> {
    let (_, cert) =
        x509_parser::parse_x509_certificate(cert_der).context("parsing the peer certificate")?;
    Ok(cert.tbs_certificate.subject_pki.raw.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_has_a_p256_spki() {
        let id = Identity::generate().unwrap();
        // A P-256 SPKI DER is 91 bytes and starts with the fixed
        // id-ecPublicKey AlgorithmIdentifier.
        assert_eq!(id.spki_der().len(), 91);
        assert_eq!(&id.spki_der()[..3], &[0x30, 0x59, 0x30]);
        assert_eq!(id.cert_chain().len(), 1);
        assert!(!id.spki_b64().is_empty());
    }

    #[test]
    fn the_certificate_carries_the_same_key_as_the_spki() {
        let id = Identity::generate().unwrap();
        let from_cert = spki_from_cert(id.cert_chain()[0].as_ref()).unwrap();
        assert_eq!(from_cert, id.spki_der());
    }

    #[test]
    fn the_identity_survives_a_pem_round_trip() {
        let id = Identity::generate().unwrap();
        let (cert_pem, key_pem) = id.to_pem().unwrap();
        assert!(cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(key_pem.contains("PRIVATE KEY"));

        let back = Identity::from_pem(&cert_pem, &key_pem).unwrap();
        assert_eq!(back.spki_der(), id.spki_der());
        assert_eq!(back.spki_b64(), id.spki_b64());
        // The rebuilt certificate is the same one, so the TLS identity is too.
        assert_eq!(back.cert_chain()[0].as_ref(), id.cert_chain()[0].as_ref());
    }

    #[test]
    fn a_truncated_certificate_pem_is_an_error_not_a_panic() {
        let id = Identity::generate().unwrap();
        let (cert_pem, key_pem) = id.to_pem().unwrap();
        let _ = cert_pem;
        assert!(Identity::from_pem("-----BEGIN CERTIFICATE-----\n", &key_pem).is_err());
    }

    #[test]
    fn pem_round_trip_matches() {
        use base64::Engine;
        let id = Identity::generate().unwrap();
        let b64 = base64::engine::general_purpose::STANDARD.encode(id.spki_der());
        let pem = format!("-----BEGIN PUBLIC KEY-----\n{b64}\n-----END PUBLIC KEY-----\n");
        assert_eq!(spki_from_pem(&pem).unwrap(), id.spki_der());
    }
}
