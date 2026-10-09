//! Provision an anonymous quick tunnel, register with the edge, and serve.
//!
//! Control plane: `POST https://api.trycloudflare.com/tunnel` returns a tunnel
//! id, hostname, account tag and 32-byte secret. Data plane: a QUIC connection
//! to `region{1,2}.v2.argotunnel.com:7844` (ALPN `argotunnel`, SNI
//! `quic.cftunnel.com`); the first bidi stream is a Cap'n Proto RPC that
//! registers the tunnel, and every later stream is one inbound request.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use cloudflare_quick_tunnel::edge::IpVersionFilter;
use cloudflare_quick_tunnel::{api, edge, quic_dial, rpc};
use tokio::sync::oneshot;
use tracing::{info, warn};
use uuid::Uuid;

use crate::origin::Origin;

pub const CLIENT_VERSION: &str = concat!("cfrs/", env!("CARGO_PKG_VERSION"));
const VERIFY_ATTEMPTS: u32 = 20;
const VERIFY_DELAY: Duration = Duration::from_secs(2);

pub struct RunArgs {
    pub origin: Origin,
    pub token: Option<String>,
    pub verify: bool,
    pub exit_on_verify: bool,
    pub run_for: Option<u64>,
    pub service_url: String,
    pub user_agent: String,
}

pub async fn run(args: RunArgs) -> Result<()> {
    let RunArgs {
        origin,
        token,
        verify,
        exit_on_verify,
        run_for,
        service_url,
        user_agent,
    } = args;

    info!("requesting anonymous quick tunnel");
    let tunnel = api::request_tunnel(&service_url, &user_agent)
        .await
        .context("provisioning quick tunnel")?;
    let url = format!("https://{}", tunnel.hostname.trim_start_matches("https://"));
    let tunnel_id = Uuid::parse_str(&tunnel.id).context("quick tunnel returned a non-UUID id")?;
    let auth = rpc::TunnelAuth {
        account_tag: tunnel.account_tag.clone(),
        tunnel_secret: tunnel.secret.clone(),
    };

    let endpoint = quic_dial::build_endpoint()?;
    let edges = edge::discover(IpVersionFilter::Auto).await?;
    if edges.is_empty() {
        bail!("edge discovery returned no addresses");
    }
    let candidates = edges.len().min(5);
    let connection = quic_dial::dial_any(&endpoint, &edges[..candidates])
        .await
        .context("QUIC handshake with the Cloudflare edge")?;

    let options = rpc::ConnectionOptions::default_for_quick_tunnel(CLIENT_VERSION);
    let (details, control) =
        rpc::register_connection(&connection, &auth, tunnel_id, 0, &options).await?;

    println!();
    println!("  cfrs: origin  {}", origin.describe());
    println!("  cfrs: public  {url}");
    println!("  cfrs: edge    {}", details.location);
    println!();

    // Verification must run while the accept loop is serving, so it is a task.
    let mut verify_rx: Option<oneshot::Receiver<Result<(), String>>> = None;
    if verify {
        let (tx, rx) = oneshot::channel();
        let expected = token.clone();
        let target = url.clone();
        tokio::spawn(async move {
            let verdict = verify_url(&target, expected.as_deref()).await;
            let _ = tx.send(verdict.map_err(|e| e.to_string()));
        });
        verify_rx = Some(rx);
    }

    let shutdown = async {
        match run_for {
            Some(secs) => tokio::time::sleep(Duration::from_secs(secs)).await,
            None => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    };
    tokio::pin!(shutdown);

    let mut verify_error: Option<String> = None;
    let mut verified = false;

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("shutdown requested");
                break;
            }
            verdict = async { verify_rx.as_mut().unwrap().await }, if verify_rx.is_some() => {
                verify_rx = None;
                match verdict {
                    Ok(Ok(())) => {
                        verified = true;
                        if exit_on_verify {
                            break;
                        }
                    }
                    Ok(Err(err)) => {
                        verify_error = Some(err);
                        break;
                    }
                    Err(_) => {}
                }
            }
            accepted = connection.accept_bi() => {
                match accepted {
                    Ok((send, recv)) => {
                        let origin = origin.clone();
                        tokio::spawn(async move {
                            crate::proxy::serve_stream(origin, send, recv).await;
                        });
                    }
                    Err(err) => {
                        warn!(error = %err, "edge closed the tunnel connection");
                        break;
                    }
                }
            }
        }
    }

    control.shutdown_graceful(Duration::from_secs(5)).await;

    if let Some(err) = verify_error {
        bail!("exposure could not be verified: {err}");
    }
    if verify && !verified {
        bail!("exposure could not be verified before shutdown");
    }
    Ok(())
}

async fn verify_url(url: &str, expected_token: Option<&str>) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())?;

    let mut last = String::from("no attempt made");
    for attempt in 1..=VERIFY_ATTEMPTS {
        match client.get(url).send().await {
            Ok(response) => {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                let token_ok = expected_token
                    .map(|token| body.contains(token))
                    .unwrap_or(true);
                if status.is_success() && token_ok {
                    println!(
                        "  cfrs: PROOF   {url} -> HTTP {} ({} bytes, token matched)",
                        status.as_u16(),
                        body.len()
                    );
                    return Ok(());
                }
                last = format!("HTTP {} body did not match", status.as_u16());
                warn!(attempt, status = %status, "unexpected response; retrying");
            }
            Err(err) => {
                last = err.to_string();
                warn!(attempt, error = %err, "public fetch failed; retrying");
            }
        }
        tokio::time::sleep(VERIFY_DELAY).await;
    }
    Err(last)
}
