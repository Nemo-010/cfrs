//! A Cloudflare quick tunnel whose edge connection is carried by WARP.
//!
//! This is the answer to "the tunnel edge is on 7844 and 7844 is filtered". The
//! edge protocol itself cannot move to 443 — Cloudflare closed the request to
//! serve `argotunnel` there ([cloudflared#79]) and the SRV record pins the port
//! to 7844 — so the connection is not moved, it is *tunnelled*: the QUIC
//! datagrams are handed to a local relay socket, which writes them into the
//! WARP MASQUE session (TCP 443), which egresses at Cloudflare and delivers them
//! to the edge on 7844. The host never opens a socket to 7844.
//!
//! [cloudflared#79]: https://github.com/cloudflare/cloudflared/issues/79
//!
//! ```no_run
//! # async fn demo() -> anyhow::Result<()> {
//! use cfrs::warp::{start_quick_tunnel, WarpClient};
//!
//! let client = WarpClient::register().await?;
//! let stack = client.connect().await?;
//! // The origin is a local HTTP server; visitors arrive on 443 at the edge.
//! let tunnel = start_quick_tunnel(stack, 8080).await?;
//! println!("{}", tunnel.url);
//! # Ok(())
//! # }
//! ```

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use cloudflare_quick_tunnel::{
    api, edge, pool, quic_dial, rpc, supervisor,
};
use tokio::sync::{oneshot, Mutex};

use super::ip::WarpStack;

/// How long to wait for the relay to see a reply before giving up on a dial.
const RELAY_DIAL_TIMEOUT: Duration = Duration::from_secs(20);

/// A local UDP socket that forwards to the tunnel edge through WARP.
pub struct EdgeRelay {
    /// The address to hand to the QUIC client as if it were the edge.
    pub local: SocketAddr,
    /// The real edge the relay forwards to.
    pub target: SocketAddr,
}

/// Start a relay from a local UDP socket to `target`, carrying every datagram
/// through `stack`.
///
/// The QUIC client dials `relay.local`; its datagrams are re-emitted on the
/// WARP tunnel to `target`, and replies are re-emitted back to whichever peer
/// last wrote to the relay. One QUIC connection means one peer, so the peer
/// address is simply remembered.
pub async fn relay_over_warp(stack: &WarpStack, target: SocketAddr) -> Result<EdgeRelay> {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .context("binding the edge relay socket")?;
    let local = socket.local_addr().context("reading the relay address")?;
    let socket = Arc::new(socket);
    let udp = stack.udp_bind().await.context("binding the WARP UDP socket")?;
    let peer: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    // Client -> WARP -> edge.
    {
        let socket = socket.clone();
        let udp = udp.clone();
        let peer = peer.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_536];
            loop {
                let (n, from) = match socket.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                *peer.lock().await = Some(from);
                if udp.send_to(buf[..n].to_vec(), target).await.is_err() {
                    break;
                }
            }
        });
    }

    // Edge -> WARP -> client.
    {
        let socket = socket.clone();
        let udp = udp;
        let peer = peer.clone();
        tokio::spawn(async move {
            loop {
                let (data, _from) = match udp.recv_from(65_536).await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let to = *peer.lock().await;
                if let Some(to) = to {
                    let _ = socket.send_to(&data, to).await;
                }
            }
        });
    }

    Ok(EdgeRelay { local, target })
}

/// A running quick tunnel.
pub struct QuickTunnelHandle {
    /// The public `https://<name>.trycloudflare.com` URL.
    pub url: String,
    /// The tunnel id the edge assigned.
    pub tunnel_id: uuid::Uuid,
    /// The edge colo the connection landed in.
    pub location: String,
    /// The real edge address the relay forwards to.
    pub edge: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    metrics: supervisor::SupervisorMetrics,
}

impl QuickTunnelHandle {
    /// Stream, byte-in and byte-out counters since the tunnel started.
    pub fn metrics(&self) -> (u64, u64, u64) {
        self.metrics.snapshot()
    }

    /// Close the tunnel.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Provision a quick tunnel and carry its edge connection over `stack`.
///
/// `local_port` is the origin the edge should reach: visitor streams are
/// proxied to `127.0.0.1:local_port`, exactly as `cloudflared --url` does.
pub async fn start_quick_tunnel(stack: WarpStack, local_port: u16) -> Result<QuickTunnelHandle> {
    // 1. Anonymous provisioning. Reachable on 443.
    let tunnel = api::request_tunnel(api::DEFAULT_SERVICE_URL, api::DEFAULT_USER_AGENT)
        .await
        .context("requesting a quick tunnel")?;
    let url = if tunnel.hostname.starts_with("https://") {
        tunnel.hostname.clone()
    } else {
        format!("https://{}", tunnel.hostname)
    };
    let tunnel_id =
        uuid::Uuid::parse_str(&tunnel.id).context("the tunnel id is not a UUID")?;

    // 2. Find the real edge. Discovery resolves the SRV record to an address on
    //    7844, which is the point: it is resolved here but dialled from inside
    //    the WARP tunnel.
    let edges = edge::discover(edge::IpVersionFilter::Auto)
        .await
        .context("discovering the tunnel edge")?;
    let Some(first) = edges.first() else {
        bail!("edge discovery returned no addresses");
    };
    let real_edge = first.socket();

    // 3. Bridge 7844 into the tunnel.
    let relay = relay_over_warp(&stack, real_edge).await?;

    // 4. Dial the relay as if it were the edge. The TLS SNI stays
    //    `quic.cftunnel.com`, so the edge sees an ordinary argotunnel
    //    handshake.
    let endpoint = quic_dial::build_endpoint().context("building the QUIC endpoint")?;
    let proxied = edge::EdgeAddr {
        ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port: relay.local.port(),
        version: edge::EdgeIpVersion::V4,
    };
    let conn = tokio::time::timeout(
        RELAY_DIAL_TIMEOUT,
        quic_dial::dial_any(&endpoint, std::slice::from_ref(&proxied)),
    )
    .await
    .context("the QUIC handshake through WARP timed out")?
    .context("the QUIC handshake through WARP failed")?;

    // 5. Register the tunnel on that connection.
    let auth = rpc::TunnelAuth {
        account_tag: tunnel.account_tag.clone(),
        tunnel_secret: tunnel.secret.clone(),
    };
    let options = rpc::ConnectionOptions::default_for_quick_tunnel(cloudflare_quick_tunnel::manager::CLIENT_VERSION);
    let (details, control) = rpc::register_connection(&conn, &auth, tunnel_id, 0, &options)
        .await
        .context("registering the tunnel on the edge")?;

    // 6. Serve visitor streams to the origin.
    let metrics = supervisor::SupervisorMetrics::default();
    let pool = Arc::new(pool::Pool::new(local_port));
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    {
        let conn = conn.clone();
        let metrics = metrics.clone();
        let pool = pool.clone();
        tokio::spawn(async move {
            let _ = supervisor::run(conn, local_port, metrics, pool, shutdown_rx).await;
        });
    }

    // Keep the control session alive for the tunnel's lifetime.
    tokio::spawn(async move {
        let _control = control;
        let _endpoint = endpoint;
        std::future::pending::<()>().await;
    });

    Ok(QuickTunnelHandle {
        url,
        tunnel_id,
        location: details.location,
        edge: real_edge,
        shutdown: Some(shutdown_tx),
        metrics,
    })
}
