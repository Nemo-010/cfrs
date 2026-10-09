//! Origin connections: TCP, TLS, unix sockets, and TLS over unix.

use std::path::PathBuf;
use std::sync::{Arc, Once, OnceLock};

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, UnixStream};
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio_rustls::TlsConnector;

use crate::ingress::{OriginOptions, Service};

pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWrite for T {}

pub type BoxedIo = Box<dyn AsyncReadWrite>;

/// Install the ring crypto provider once per process. `cloudflare-quick-tunnel`
/// also does this; calling it early keeps every rustls user consistent.
pub fn init_crypto() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    });
}

/// Dial the origin for a forward service.
pub async fn dial(service: &Service, options: &OriginOptions) -> Result<BoxedIo> {
    let timeout = options.connect_timeout;
    let connect = async {
        match service {
            Service::Http(url) => {
                let (host, port, tls) = parse_http_url(url)?;
                let tcp = TcpStream::connect((host.as_str(), port))
                    .await
                    .with_context(|| format!("connecting to {host}:{port}"))?;
                if tls {
                    tls_wrap(tcp, &host, options.no_tls_verify).await
                } else {
                    Ok(Box::new(tcp) as BoxedIo)
                }
            }
            Service::Unix(path) => UnixStream::connect(path)
                .await
                .map(|s| Box::new(s) as BoxedIo)
                .with_context(|| format!("connecting to unix:{}", path.display())),
            Service::UnixTls(path) => {
                let stream = UnixStream::connect(path)
                    .await
                    .with_context(|| format!("connecting to unix:{}", path.display()))?;
                tls_wrap(stream, "localhost", options.no_tls_verify).await
            }
            Service::Tcp(addr) => TcpStream::connect(addr.as_str())
                .await
                .map(|s| Box::new(s) as BoxedIo)
                .with_context(|| format!("connecting to {addr}")),
            other => bail!("{} is not a forward service", other.describe()),
        }
    };
    match timeout {
        Some(limit) => tokio::time::timeout(limit, connect)
            .await
            .map_err(|_| anyhow::anyhow!("origin connect timed out after {limit:?}"))?,
        None => connect.await,
    }
}

/// Parse `http(s)://host[:port]` into `(host, port, tls)`.
pub fn parse_http_url(url: &str) -> Result<(String, u16, bool)> {
    let (scheme, rest) = url
        .split_once("://")
        .context("origin URL is missing a scheme")?;
    let tls = match scheme {
        "http" => false,
        "https" => true,
        other => bail!("unsupported origin scheme {other:?}"),
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        bail!("origin URL has no host");
    }
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, rest) = rest
            .split_once(']')
            .context("origin URL has an unclosed IPv6 address")?;
        let port = match rest.strip_prefix(':') {
            Some(port) => port.parse().context("origin URL port is invalid")?,
            None if rest.is_empty() => {
                if tls {
                    443
                } else {
                    80
                }
            }
            None => bail!("origin URL has trailing characters after the IPv6 address"),
        };
        (host.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) if !port.contains(']') => {
                let port: u16 = port.parse().context("origin URL port is invalid")?;
                (host.to_string(), port)
            }
            _ => (authority.to_string(), if tls { 443 } else { 80 }),
        }
    };
    if host.is_empty() {
        bail!("origin URL has no host");
    }
    Ok((host, port, tls))
}

async fn tls_wrap<S>(stream: S, server_name: &str, no_verify: bool) -> Result<BoxedIo>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let connector = if no_verify {
        no_verify_connector()
    } else {
        verified_connector()
    };
    let name = ServerName::try_from(server_name.to_string())
        .map_err(|_| anyhow::anyhow!("invalid TLS server name {server_name:?}"))?;
    let tls = connector
        .connect(name, stream)
        .await
        .with_context(|| format!("TLS handshake with {server_name}"))?;
    Ok(Box::new(tls))
}

fn verified_connector() -> TlsConnector {
    static ONCE: OnceLock<TlsConnector> = OnceLock::new();
    ONCE.get_or_init(|| {
        init_crypto();
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        TlsConnector::from(Arc::new(config))
    })
    .clone()
}

fn no_verify_connector() -> TlsConnector {
    static ONCE: OnceLock<TlsConnector> = OnceLock::new();
    ONCE.get_or_init(|| {
        init_crypto();
        let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
            .with_no_client_auth();
        TlsConnector::from(Arc::new(config))
    })
    .clone()
}

#[derive(Debug)]
struct NoVerify(Arc<tokio_rustls::rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Convenience: the origin path for a service, used by logs.
pub fn origin_label(service: &Service) -> String {
    match service {
        Service::Unix(path) => format!("unix:{}", path.display()),
        Service::UnixTls(path) => format!("unix+tls:{}", path.display()),
        other => other.describe(),
    }
}

/// Keep `PathBuf` referenced so the import is used on every platform.
#[allow(dead_code)]
fn _pathbuf(_: PathBuf) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_urls() {
        assert_eq!(parse_http_url("http://127.0.0.1:8080").unwrap(), ("127.0.0.1".into(), 8080, false));
        assert_eq!(parse_http_url("https://example.com").unwrap(), ("example.com".into(), 443, true));
        assert_eq!(parse_http_url("http://example.com/x").unwrap(), ("example.com".into(), 80, false));
        assert_eq!(parse_http_url("https://[::1]:8443").unwrap(), ("::1".into(), 8443, true));
        assert!(parse_http_url("ftp://x").is_err());
        assert!(parse_http_url("http://").is_err());
    }
}
