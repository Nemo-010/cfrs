//! WebSocket-carried raw streams.
//!
//! A quick tunnel is an HTTP tunnel, but it proxies WebSocket upgrades. That is
//! enough to carry *anything*: the origin exposes a WebSocket endpoint, each
//! connection is bridged to a raw stream (TCP or unix), and a client on the far
//! side turns local sockets into WebSocket connections. This is the websocat /
//! wstunnel idea, and it removes the HTTP-only limit without needing the edge to
//! understand the payload.
//!
//! One WebSocket message maps to one write, so binary framing is preserved and
//! interactive protocols (SSH, RDP, databases, raw sockets) work unchanged.

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use cloudflare_quick_tunnel::stream as cqstream;
use futures::{SinkExt as _, StreamExt as _};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use crate::ingress::{ForwardTarget, OriginOptions, Service};
use crate::metrics::Metrics;
use crate::net::{self, BoxedIo};
use crate::proxy::{header_value, write_response_meta, EdgeReader, EdgeWriter};

/// The RFC 6455 handshake GUID.
const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Default path for a `--forward` WebSocket endpoint.
pub const DEFAULT_PATH: &str = "/__cfrs/ws";

/// Compute `Sec-WebSocket-Accept` for a client's `Sec-WebSocket-Key`.
pub fn accept_key(key: &str) -> String {
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(WS_GUID);
    base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
}

/// Serve one inbound WebSocket upgrade from the edge, bridging it to `target`.
pub async fn serve_websocket(
    target: &ForwardTarget,
    request: &cqstream::ConnectRequest,
    reader: EdgeReader,
    mut writer: EdgeWriter,
    metrics: &Metrics,
) -> Result<()> {
    let Some(key) = header_value(request, "sec-websocket-key") else {
        return write_response_meta(&mut writer, 400, &plain("missing Sec-WebSocket-Key"))
            .await;
    };

    let headers = vec![
        ("Upgrade".to_string(), "websocket".to_string()),
        ("Connection".to_string(), "Upgrade".to_string()),
        ("Sec-WebSocket-Accept".to_string(), accept_key(key)),
    ];
    write_response_meta(&mut writer, 101, &headers).await?;

    let service = match target {
        ForwardTarget::Tcp(addr) => Service::Tcp(addr.clone()),
        ForwardTarget::Unix(path) => Service::Unix(path.clone()),
    };
    let io = net::dial(&service, &OriginOptions::default())
        .await
        .with_context(|| format!("dialing forward target {}", target.describe()))?;

    // The edge stream is a QUIC bidi pair; join it into one socket for the
    // WebSocket codec. `into_inner` recovers the quinn halves from the
    // futures-io wrappers used by the request framing.
    let socket = tokio::io::join(reader.into_inner(), writer.into_inner());
    let ws = WebSocketStream::from_raw_socket(socket, Role::Server, None).await;
    bridge(ws, io, metrics).await
}

/// Connect a local socket to a remote WebSocket endpoint.
pub async fn connect_bridge(url: &str, io: BoxedIo) -> Result<()> {
    let (ws, _response) = tokio_tungstenite::connect_async(url)
        .await
        .with_context(|| format!("connecting to {url}"))?;
    bridge(ws, io, &Metrics::new()).await
}

/// Pump bytes both ways between a WebSocket and a raw stream.
pub async fn bridge<S>(ws: WebSocketStream<S>, io: BoxedIo, metrics: &Metrics) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sink, mut stream) = ws.split();
    let (mut io_r, mut io_w) = tokio::io::split(io);
    let (control_tx, mut control_rx) = tokio::sync::mpsc::channel::<Message>(16);
    let in_metrics = metrics.clone();
    let out_metrics = metrics.clone();

    let ws_to_io = async move {
        while let Some(message) = stream.next().await {
            let message = message.context("websocket read")?;
            match message {
                Message::Binary(bytes) => {
                    io_w.write_all(&bytes).await?;
                    in_metrics.add_in(bytes.len() as u64);
                }
                Message::Text(text) => {
                    io_w.write_all(text.as_bytes()).await?;
                    in_metrics.add_in(text.len() as u64);
                }
                Message::Ping(payload) => {
                    let _ = control_tx.send(Message::Pong(payload)).await;
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
        let _ = io_w.shutdown().await;
        Ok::<(), anyhow::Error>(())
    };

    let io_to_ws = async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            tokio::select! {
                maybe = control_rx.recv() => {
                    match maybe {
                        Some(message) => {
                            if sink.send(message).await.is_err() {
                                break;
                            }
                        }
                        None => break,
                    }
                }
                read = io_r.read(&mut buf) => {
                    let n = read?;
                    if n == 0 {
                        break;
                    }
                    out_metrics.add_out(n as u64);
                    if sink
                        .send(Message::Binary(buf[..n].to_vec()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
        let _ = sink.close().await;
        Ok::<(), anyhow::Error>(())
    };

    let (to_io, to_ws) = tokio::join!(ws_to_io, io_to_ws);
    to_io?;
    to_ws
}

fn plain(message: &str) -> Vec<(String, String)> {
    vec![
        ("Content-Type".to_string(), "text/plain; charset=utf-8".to_string()),
        ("Content-Length".to_string(), message.len().to_string()),
    ]
}

/// A local listener specification for `cfrs connect`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalSpec {
    /// `tcp://[bind:]port`
    Tcp { bind: String, port: u16 },
    /// `unix:///path`
    Unix(std::path::PathBuf),
}

impl LocalSpec {
    pub fn parse(value: &str) -> Result<Self> {
        let value = value.trim();
        if let Some(rest) = value.strip_prefix("tcp://") {
            let (bind, port) = match rest.rsplit_once(':') {
                Some((bind, port)) => (bind.to_string(), port),
                None => ("127.0.0.1".to_string(), rest),
            };
            let port: u16 = port.parse().context("local TCP port is invalid")?;
            let bind = if bind.is_empty() { "127.0.0.1".to_string() } else { bind };
            return Ok(Self::Tcp { bind, port });
        }
        for prefix in ["unix://", "unix:"] {
            if let Some(rest) = value.strip_prefix(prefix) {
                if rest.is_empty() {
                    bail!("local unix socket has no path: {value:?}");
                }
                return Ok(Self::Unix(std::path::PathBuf::from(rest)));
            }
        }
        bail!("local listener must be tcp://[bind:]port or unix:///path, got {value:?}")
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Tcp { bind, port } => format!("tcp://{bind}:{port}"),
            Self::Unix(path) => format!("unix:{}", path.display()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_key_matches_rfc_example() {
        // RFC 6455 section 1.3.
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn parses_local_specs() {
        assert_eq!(
            LocalSpec::parse("tcp://8080").unwrap(),
            LocalSpec::Tcp { bind: "127.0.0.1".into(), port: 8080 }
        );
        assert_eq!(
            LocalSpec::parse("tcp://0.0.0.0:9000").unwrap(),
            LocalSpec::Tcp { bind: "0.0.0.0".into(), port: 9000 }
        );
        assert_eq!(
            LocalSpec::parse("unix:///tmp/f.sock").unwrap(),
            LocalSpec::Unix("/tmp/f.sock".into())
        );
        assert!(LocalSpec::parse("http://x").is_err());
        assert!(LocalSpec::parse("tcp://nope").is_err());
    }

    #[tokio::test]
    async fn bridge_moves_bytes_both_ways() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let (edge_server, edge_client) = tokio::io::duplex(1 << 16);
        let (target_a, mut target_b) = tokio::io::duplex(1 << 16);

        let server = tokio::spawn(async move {
            let ws = WebSocketStream::from_raw_socket(edge_server, Role::Server, None).await;
            bridge(ws, Box::new(target_a), &Metrics::new()).await
        });

        // The handshake is covered by `accept_key_matches_rfc_example`; here we
        // drive the framing directly on both ends.
        let mut ws = WebSocketStream::from_raw_socket(edge_client, Role::Client, None).await;

        // client -> target
        ws.send(Message::Binary(b"hello".to_vec())).await.unwrap();
        let mut buf = [0u8; 5];
        target_b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        // target -> client
        target_b.write_all(b"world").await.unwrap();
        let message = ws.next().await.unwrap().unwrap();
        assert_eq!(message, Message::Binary(b"world".to_vec()));

        drop(ws);
        let _ = server.await.unwrap();
    }
}
