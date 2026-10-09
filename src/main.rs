//! cfrs — expose a local server on the public Electrosphere through an
//! anonymous Cloudflare quick tunnel (`https://<random>.trycloudflare.com`).
//!
//! Two things make this usable from a sealed sandbox: the local origin may be
//! an `AF_UNIX` socket (where `bind(2)` on `AF_INET` is refused), and the
//! transport is QUIC over UDP/7844 (where outbound TCP/7844 is blocked). See
//! `PROTOCOL.md` for the measurements and the wire protocol.

mod origin;
mod proxy;
mod tunnel;

use std::time::Duration;

use anyhow::{bail, Result};
use clap::Parser;
use tracing_subscriber::EnvFilter;

/// Expose a local HTTP server on the public Electrosphere via an anonymous
/// Cloudflare quick tunnel. No Cloudflare account, no API token.
#[derive(Debug, Parser)]
#[command(name = "cfrs", version, about, long_about = None)]
struct Cli {
    /// Expose an HTTP server already listening on this unix socket path.
    #[arg(long, value_name = "PATH", conflicts_with = "port")]
    unix: Option<std::path::PathBuf>,

    /// Expose an HTTP server on this TCP port on 127.0.0.1 (normal hosts).
    #[arg(long, value_name = "PORT", conflicts_with = "unix")]
    port: Option<u16>,

    /// Start a built-in unix-socket origin (no external server needed) and
    /// expose it. Ends with a fetch of the public URL as proof.
    #[arg(long, conflicts_with_all = ["unix", "port"])]
    demo: bool,

    /// Socket path for the built-in demo origin.
    #[arg(long, value_name = "PATH", default_value = "/tmp/cfrs-demo.sock")]
    demo_socket: std::path::PathBuf,

    /// Do not fetch the public URL to prove reachability.
    #[arg(long)]
    no_verify: bool,

    /// Exit once the public URL has been verified (instead of serving until
    /// Ctrl-C). Useful in scripts and CI.
    #[arg(long)]
    exit_on_verify: bool,

    /// Stay up for this many seconds instead of until Ctrl-C.
    #[arg(long, value_name = "SECS")]
    run_for: Option<u64>,

    /// Quick-tunnel provisioning endpoint.
    #[arg(
        long,
        value_name = "URL",
        default_value = "https://api.trycloudflare.com"
    )]
    service_url: String,

    /// User-Agent sent when provisioning.
    #[arg(long, value_name = "UA", default_value = "cloudflared/2024.12.0")]
    user_agent: String,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("cfrs=info,cloudflare_quick_tunnel=warn")),
        )
        .init();

    let cli = Cli::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run(cli))
}

async fn run(cli: Cli) -> Result<()> {
    let (origin, token) = if cli.demo {
        let token = origin::random_token();
        let path = cli.demo_socket.clone();
        let served = token.clone();
        tokio::spawn(async move {
            if let Err(err) = origin::serve_demo(path.clone(), served).await {
                eprintln!("cfrs: demo origin failed: {err}");
            }
        });
        // The listener binds synchronously inside the task; wait for the
        // socket to appear before dialling it.
        for _ in 0..100 {
            if cli.demo_socket.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        (origin::Origin::Unix(cli.demo_socket.clone()), Some(token))
    } else if let Some(path) = cli.unix.clone() {
        (origin::Origin::Unix(path), None)
    } else if let Some(port) = cli.port {
        (origin::Origin::Tcp(format!("127.0.0.1:{port}")), None)
    } else {
        bail!("choose an origin: --demo, --unix <path>, or --port <port>");
    };

    tunnel::run(tunnel::RunArgs {
        origin,
        token,
        verify: !cli.no_verify,
        exit_on_verify: cli.exit_on_verify,
        run_for: cli.run_for,
        service_url: cli.service_url,
        user_agent: cli.user_agent,
    })
    .await
}
