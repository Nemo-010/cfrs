//! A MASQUE CONNECT-IP session over HTTP/2 on TCP 443.
//!
//! This is the transport that makes the tunnel work where only 443 and 80 are
//! permitted: the MASQUE front door speaks HTTP/2 as happily as HTTP/3, and the
//! CONNECT-IP request is an ordinary `CONNECT` with a `cf-connect-proto` header
//! rather than an HTTP/3 extended connect with a `:protocol` pseudo-header. IP
//! packets then travel as capsules in the request body, in both directions.
//!
//! The credential is mutual TLS: the client certificate enrolled through
//! [`super::register::enrol_masque`] authenticates the device, and the server's
//! certificate is pinned to the SPKI the API returned.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use bytes::{Bytes, BytesMut};
use http::{Method, Request, StatusCode};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use super::capsule::{self, CapsuleDecoder};
use super::identity::Identity;
use super::register::{CONNECT_URI, MASQUE_SNI};

/// How long to wait for the TCP connect, TLS handshake and CONNECT response.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Verify the server only against a pinned SubjectPublicKeyInfo.
///
/// The front door's certificate is not issued by a public CA and its name is not
/// the address we dial, so ordinary chain validation cannot apply. What is
/// verified instead is the exact key the API told us to trust; a certificate
/// with a different key is refused.
#[derive(Debug)]
struct PinnedKey {
    expected: Option<Vec<u8>>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for PinnedKey {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if let Some(expected) = &self.expected {
            let got = super::identity::spki_from_cert(end_entity.as_ref())
                .map_err(|_| rustls::Error::General("unparsable peer certificate".into()))?;
            if &got != expected {
                return Err(rustls::Error::General(
                    "MASQUE peer key does not match the pinned key".into(),
                ));
            }
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn tls_config(identity: &Identity, pinned_spki: Option<Vec<u8>>) -> Result<Arc<ClientConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(PinnedKey {
        expected: pinned_spki,
        provider: Arc::clone(&provider),
    });
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(RootCertStore::empty())
        .with_client_auth_cert(identity.cert_chain(), identity.private_key())
        .context("installing the MASQUE client certificate")?;
    config
        .dangerous()
        .set_certificate_verifier(verifier);
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(Arc::new(config))
}

/// An established CONNECT-IP session.
pub struct MasqueSession {
    ping: Option<h2::PingPong>,
    send: h2::SendStream<Bytes>,
    recv: h2::RecvStream,
    decoder: CapsuleDecoder,
    /// Set once the body stream ends.
    closed: bool,
}

/// The write half of a session, moved to whatever task pumps outbound packets.
pub struct MasqueTx {
    ping: Option<h2::PingPong>,
    send: h2::SendStream<Bytes>,
    closed: bool,
}

/// The read half of a session, moved to whatever task pumps inbound packets.
pub struct MasqueRx {
    recv: h2::RecvStream,
    decoder: CapsuleDecoder,
    closed: bool,
}

impl MasqueSession {
    /// Dial the MASQUE front door over TCP and open the CONNECT-IP tunnel.
    pub async fn connect(
        endpoint: std::net::SocketAddr,
        identity: &Identity,
        pinned_spki: Option<Vec<u8>>,
    ) -> Result<Self> {
        tokio::time::timeout(
            CONNECT_TIMEOUT,
            Self::connect_inner(endpoint, identity, pinned_spki),
        )
        .await
        .context("MASQUE connect timed out")?
    }

    async fn connect_inner(
        endpoint: std::net::SocketAddr,
        identity: &Identity,
        pinned_spki: Option<Vec<u8>>,
    ) -> Result<Self> {
        let tcp = TcpStream::connect(endpoint)
            .await
            .with_context(|| format!("TCP connect to the MASQUE front door {endpoint}"))?;
        tcp.set_nodelay(true).ok();

        let config = tls_config(identity, pinned_spki)?;
        let server_name = ServerName::try_from(MASQUE_SNI)
            .context("invalid MASQUE SNI")?
            .to_owned();
        let tls = TlsConnector::from(config)
            .connect(server_name, tcp)
            .await
            .context("TLS handshake with the MASQUE front door")?;

        let (client, mut connection) = h2::client::handshake(tls)
            .await
            .context("HTTP/2 handshake with the MASQUE front door")?;
        // Grab the PING handle before the connection is moved to its task;
        // a MASQUE tunnel that goes idle for too long is torn down by the edge.
        let ping = connection.ping_pong();
        tokio::spawn(async move {
            if let Err(err) = connection.await {
                tracing::debug!(%err, "MASQUE HTTP/2 connection closed");
            }
        });

        let mut client = client.ready().await.context("HTTP/2 client not ready")?;

        let request = Request::builder()
            .method(Method::CONNECT)
            .uri(CONNECT_URI)
            .header("cf-connect-proto", "cf-connect-ip")
            .header("capsule-protocol", "?1")
            .header("pq-enabled", "false")
            .header("user-agent", "")
            .body(())
            .context("building the CONNECT-IP request")?;

        let (response, send) = client
            .send_request(request, false)
            .context("sending the CONNECT-IP request")?;

        let response = response.await.context("awaiting the CONNECT-IP response")?;
        let status = response.status();
        if status != StatusCode::OK {
            bail!(
                "CONNECT-IP refused with {status}{}",
                if status.as_u16() == 403 {
                    " (the enrolled certificate was not accepted)"
                } else {
                    ""
                }
            );
        }

        Ok(Self {
            ping,
            send,
            recv: response.into_body(),
            decoder: CapsuleDecoder::new(),
            closed: false,
        })
    }

    /// Split into a write half and a read half so the two directions can be
    /// pumped from different tasks.
    pub fn split(self) -> (MasqueTx, MasqueRx) {
        (
            MasqueTx {
                ping: self.ping,
                send: self.send,
                closed: self.closed,
            },
            MasqueRx {
                recv: self.recv,
                decoder: self.decoder,
                closed: self.closed,
            },
        )
    }

    /// Send one IP packet through the tunnel.
    pub fn send_packet(&mut self, packet: &[u8]) -> Result<()> {
        if self.closed {
            bail!("the MASQUE session is closed");
        }
        let mut buf = BytesMut::with_capacity(packet.len() + 3);
        capsule::put_capsule(&mut buf, capsule::CAPSULE_DATA, packet);
        self.send
            .send_data(buf.freeze(), false)
            .context("writing a CONNECT-IP DATA capsule")?;
        Ok(())
    }

    /// Receive one IP packet, waiting for more body bytes if needed.
    pub async fn recv_packet(&mut self) -> Result<Option<Bytes>> {
        loop {
            if let Some(packet) = self.decoder.next_packet() {
                return Ok(Some(packet));
            }
            if self.closed {
                return Ok(None);
            }
            match self.recv.data().await {
                Some(Ok(data)) => {
                    let _ = self.recv.flow_control().release_capacity(data.len());
                    self.decoder.push(&data);
                }
                Some(Err(err)) => {
                    self.closed = true;
                    bail!("reading the CONNECT-IP body: {err}");
                }
                None => {
                    self.closed = true;
                    return Ok(None);
                }
            }
        }
    }
}

impl MasqueTx {
    /// Send one IP packet through the tunnel.
    pub fn send_packet(&mut self, packet: &[u8]) -> Result<()> {
        if self.closed {
            bail!("the MASQUE session is closed");
        }
        let mut buf = BytesMut::with_capacity(packet.len() + 3);
        capsule::put_capsule(&mut buf, capsule::CAPSULE_DATA, packet);
        self.send
            .send_data(buf.freeze(), false)
            .context("writing a CONNECT-IP DATA capsule")?;
        Ok(())
    }

    /// Send an HTTP/2 PING to keep the connection alive through idle periods.
    pub fn keepalive(&mut self) -> Result<()> {
        if self.closed {
            bail!("the MASQUE session is closed");
        }
        match self.ping.as_mut() {
            Some(ping) => ping
                .send_ping(h2::Ping::opaque())
                .context("sending an HTTP/2 PING")?,
            None => bail!("HTTP/2 PING is unavailable on this connection"),
        }
        Ok(())
    }

    /// Close the request body, which tears the tunnel down.
    pub fn close(&mut self) -> Result<()> {
        if !self.closed {
            self.send
                .send_data(Bytes::new(), true)
                .context("closing the CONNECT-IP body")?;
            self.closed = true;
        }
        Ok(())
    }
}

impl MasqueRx {
    /// Receive one IP packet, waiting for more body bytes if needed.
    pub async fn recv_packet(&mut self) -> Result<Option<Bytes>> {
        loop {
            if let Some(packet) = self.decoder.next_packet() {
                return Ok(Some(packet));
            }
            if self.closed {
                return Ok(None);
            }
            match self.recv.data().await {
                Some(Ok(data)) => {
                    let _ = self.recv.flow_control().release_capacity(data.len());
                    self.decoder.push(&data);
                }
                Some(Err(err)) => {
                    self.closed = true;
                    bail!("reading the CONNECT-IP body: {err}");
                }
                None => {
                    self.closed = true;
                    return Ok(None);
                }
            }
        }
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }
}
