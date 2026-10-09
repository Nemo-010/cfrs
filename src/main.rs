//! cfrs command line.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use tracing_subscriber::EnvFilter;

use cfrs::config::{load_file, Config};
use cfrs::gate::Gate;
use cfrs::ingress::{ForwardTarget, Ingress, IngressRule, OriginOptions, Service};
use cfrs::net::BoxedIo;
use cfrs::share::{ShareConfig, ShareControl, ShareMode};
use cfrs::ws::{self, LocalSpec};
use cfrs::{Protocol, Tunnel};

#[derive(Parser, Debug)]
#[command(name = "cfrs", version, about = "Expose anything on the public Electrosphere through Cloudflare tunnels")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Expose a service (cloudflared-style).
    Tunnel(TunnelArgs),
    /// Serve a directory over a tunnel.
    Serve(ServeArgs),
    /// Upload / download / proxy session (quickbridge-style).
    Share(ShareArgs),
    /// Bridge a local socket to a remote WebSocket forward endpoint.
    Connect(ConnectArgs),
    /// List local TCP ports that are listening.
    Ports,
    /// Print a QR code for a URL.
    Qr(QrArgs),
    /// Self-contained proof: built-in origin, tunnel, then fetch the URL.
    Demo(DemoArgs),
}

#[derive(Args, Clone, Debug)]
struct TunnelOpts {
    /// Quick-tunnel provisioning endpoint.
    #[arg(long, default_value = "https://api.trycloudflare.com", global = true)]
    service_url: String,
    /// User-Agent sent when provisioning.
    #[arg(long, global = true)]
    user_agent: Option<String>,
    /// Parallel edge connections (1-8).
    #[arg(long, default_value_t = 2, global = true)]
    ha_connections: u8,
    /// Edge transport: auto, quic or http2.
    #[arg(long, default_value = "auto", global = true)]
    protocol: String,
    /// Do not fetch the public URL to prove reachability.
    #[arg(long, global = true)]
    no_verify: bool,
    /// Print a QR code for the public URL.
    #[arg(long, global = true)]
    qr: bool,
    /// Stay up for this many seconds instead of until Ctrl-C.
    #[arg(long, global = true)]
    run_for: Option<u64>,
}

impl TunnelOpts {
    fn apply(&self, mut config: Config) -> Result<Config> {
        config.service_url = self.service_url.clone();
        if let Some(user_agent) = &self.user_agent {
            config.user_agent = user_agent.clone();
        }
        config.ha_connections = self.ha_connections.clamp(1, 8);
        config.protocol = Protocol::parse(&self.protocol)?;
        config.verify = !self.no_verify;
        Ok(config)
    }
}

#[derive(Args, Debug)]
struct TunnelArgs {
    #[command(flatten)]
    common: TunnelOpts,
    /// HTTP or HTTPS origin.
    #[arg(long)]
    url: Option<String>,
    /// HTTP origin on a unix socket.
    #[arg(long)]
    unix: Option<PathBuf>,
    /// HTTP origin on 127.0.0.1:<PORT>.
    #[arg(long)]
    port: Option<u16>,
    /// Raw TCP origin.
    #[arg(long)]
    tcp: Option<String>,
    /// Expose a raw stream over a WebSocket endpoint (tcp://host:port or unix:/path).
    #[arg(long)]
    forward: Option<String>,
    /// cloudflared's built-in hello world.
    #[arg(long)]
    hello_world: bool,
    /// cloudflared-style YAML config with ingress rules.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Named-tunnel token.
    #[arg(long)]
    token: Option<String>,
    /// cloudflared credentials JSON file.
    #[arg(long)]
    credentials_file: Option<PathBuf>,
    /// Skip TLS verification of the origin.
    #[arg(long)]
    no_tls_verify: bool,
    /// Override the Host header sent to the origin.
    #[arg(long)]
    http_host_header: Option<String>,
    /// Drop Accept-Encoding so the origin cannot compress a streaming response.
    #[arg(long)]
    strip_accept_encoding: bool,
}

#[derive(Args, Debug)]
struct ServeArgs {
    #[command(flatten)]
    common: TunnelOpts,
    /// Directory to serve.
    #[arg(long, value_name = "DIR")]
    dir: PathBuf,
    /// Single-page-app fallback to index.html.
    #[arg(long)]
    spa: bool,
    /// Named-tunnel token.
    #[arg(long)]
    token: Option<String>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ModeArg {
    Upload,
    Download,
    Proxy,
}

#[derive(Args, Debug)]
struct ShareArgs {
    #[command(flatten)]
    common: TunnelOpts,
    /// Session mode.
    #[arg(long, value_enum, default_value_t = ModeArg::Upload)]
    mode: ModeArg,
    /// Directory that receives uploads.
    #[arg(long)]
    dir: Option<PathBuf>,
    /// File to share (download mode).
    #[arg(long)]
    file: Option<PathBuf>,
    /// Local HTTP port to share (proxy mode).
    #[arg(long)]
    port: Option<u16>,
    /// Require a 6-digit PIN (always on for proxy mode).
    #[arg(long)]
    password: bool,
    /// Stop the tunnel after the first successful transfer.
    #[arg(long)]
    stop_after: bool,
    /// Stop after this many idle seconds (0 disables).
    #[arg(long, default_value_t = 900)]
    idle_secs: u64,
    /// Named-tunnel token.
    #[arg(long)]
    token: Option<String>,
}

#[derive(Args, Debug)]
struct ConnectArgs {
    /// Public WebSocket URL, e.g. wss://<host>/__cfrs/ws.
    remote: String,
    /// Local listeners, repeatable: tcp://[bind:]port or unix:///path.
    #[arg(short = 'L', long = "local", required = true)]
    locals: Vec<String>,
    /// Stay up for this many seconds instead of until Ctrl-C.
    #[arg(long)]
    run_for: Option<u64>,
}

#[derive(Args, Debug)]
struct QrArgs {
    /// URL to encode.
    url: String,
}

#[derive(Args, Debug)]
struct DemoArgs {
    #[command(flatten)]
    common: TunnelOpts,
    /// Exit as soon as the public URL has been fetched.
    #[arg(long)]
    exit_on_verify: bool,
    /// Named-tunnel token.
    #[arg(long)]
    token: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("cfrs=info,cloudflare_quick_tunnel=warn")),
        )
        .init();
    match Cli::parse().command {
        Command::Tunnel(args) => tunnel(args).await,
        Command::Serve(args) => serve(args).await,
        Command::Share(args) => share(args).await,
        Command::Connect(args) => connect(args).await,
        Command::Ports => {
            for port in cfrs::ports::listening_ports() {
                println!("{port}");
            }
            Ok(())
        }
        Command::Qr(args) => {
            print!("{}", cfrs::qr::render_terminal(&args.url)?);
            Ok(())
        }
        Command::Demo(args) => demo(args).await,
    }
}

async fn tunnel(args: TunnelArgs) -> Result<()> {
    let mut config = if let Some(path) = &args.config {
        load_file(path)?
    } else {
        Config::default()
    };
    if let Some(token) = &args.token {
        config.credentials = cfrs::config::parse_token(token)?;
    } else if let Some(path) = &args.credentials_file {
        config.credentials = cfrs::config::parse_credentials_file(path)?;
    }

    if args.config.is_none() {
        let mut ingress = Ingress::new();
        if let Some(forward) = &args.forward {
            let target = ForwardTarget::parse(forward)?;
            ingress = ingress.rule_with(IngressRule {
                hostname: None,
                path: Some(cfrs::ws::DEFAULT_PATH.to_string()),
                service: Service::Forward(target),
                origin: OriginOptions::default(),
            });
        }
        if let Some(service) = pick_optional_service(&args)? {
            let origin = OriginOptions {
                no_tls_verify: args.no_tls_verify,
                http_host_header: args.http_host_header.clone(),
                strip_accept_encoding: args.strip_accept_encoding,
                ..OriginOptions::default()
            };
            ingress = ingress.rule_with(IngressRule {
                hostname: None,
                path: None,
                service,
                origin,
            });
        }
        if ingress.is_empty() {
            bail!(
                "choose an origin (--url, --unix, --port, --tcp, --hello-world) or --forward"
            );
        }
        config.ingress = ingress;
    }
    config = args.common.apply(config)?;
    // A forward-only tunnel has no HTTP origin to verify; the root is expected
    // to answer 503.
    if !config
        .ingress
        .rules
        .iter()
        .any(|rule| !matches!(rule.service, Service::Forward(_)))
    {
        config.verify = false;
    }

    run_tunnel(config, args.common.qr, args.common.run_for, vec![]).await
}

fn pick_optional_service(args: &TunnelArgs) -> Result<Option<Service>> {
    let mut choices = 0;
    let mut service = None;
    if let Some(url) = &args.url {
        choices += 1;
        service = Some(Service::parse(url)?);
    }
    if let Some(path) = &args.unix {
        choices += 1;
        service = Some(Service::Unix(path.clone()));
    }
    if let Some(port) = args.port {
        choices += 1;
        service = Some(Service::Http(format!("http://127.0.0.1:{port}")));
    }
    if let Some(addr) = &args.tcp {
        choices += 1;
        service = Some(Service::Tcp(addr.clone()));
    }
    if args.hello_world {
        choices += 1;
        service = Some(Service::HelloWorld);
    }
    if choices > 1 {
        bail!("choose at most one origin: --url, --unix, --port, --tcp, --hello-world");
    }
    Ok(service)
}

async fn connect(args: ConnectArgs) -> Result<()> {
    cfrs::init_crypto();
    let mut tasks = Vec::new();
    for raw in &args.locals {
        let local = LocalSpec::parse(raw)?;
        let remote = args.remote.clone();
        match local {
            LocalSpec::Tcp { bind, port } => {
                let listener = tokio::net::TcpListener::bind((bind.as_str(), port))
                    .await
                    .with_context(|| format!("binding {bind}:{port}"))?;
                println!("cfrs: {} -> {remote}", LocalSpec::Tcp { bind: bind.clone(), port }.describe());
                tasks.push(tokio::spawn(accept_loop(listener, remote)));
            }
            LocalSpec::Unix(path) => {
                #[cfg(unix)]
                {
                    let listener = unix_listener(&path)?;
                    println!("cfrs: {} -> {remote}", LocalSpec::Unix(path.clone()).describe());
                    tasks.push(tokio::spawn(accept_unix(listener, remote)));
                }
                #[cfg(not(unix))]
                {
                    let _ = remote;
                    bail!(
                        "unix sockets are not supported on this platform: {}",
                        path.display()
                    );
                }
            }
        }
    }
    match args.run_for {
        Some(secs) => tokio::time::sleep(Duration::from_secs(secs)).await,
        None => {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
    for task in tasks {
        task.abort();
    }
    Ok(())
}

async fn accept_loop(listener: tokio::net::TcpListener, remote: String) {
    loop {
        match listener.accept().await {
            Ok((stream, _peer)) => {
                let remote = remote.clone();
                tokio::spawn(async move {
                    let io: BoxedIo = Box::new(stream);
                    if let Err(err) = ws::connect_bridge(&remote, io).await {
                        tracing::warn!(error = %format!("{err:#}"), "forward connection failed");
                    }
                });
            }
            Err(err) => {
                tracing::warn!(error = %err, "accept failed");
                return;
            }
        }
    }
}

#[cfg(unix)]
fn unix_listener(path: &std::path::Path) -> Result<tokio::net::UnixListener> {
    let _ = std::fs::remove_file(path);
    tokio::net::UnixListener::bind(path)
        .with_context(|| format!("binding unix:{}", path.display()))
}

#[cfg(unix)]
async fn accept_unix(listener: tokio::net::UnixListener, remote: String) {
    loop {
        match listener.accept().await {
            Ok((stream, _peer)) => {
                let remote = remote.clone();
                tokio::spawn(async move {
                    let io: BoxedIo = Box::new(stream);
                    if let Err(err) = ws::connect_bridge(&remote, io).await {
                        tracing::warn!(error = %format!("{err:#}"), "forward connection failed");
                    }
                });
            }
            Err(err) => {
                tracing::warn!(error = %err, "accept failed");
                return;
            }
        }
    }
}

async fn serve(args: ServeArgs) -> Result<()> {
    let mut config = Config::default();
    if let Some(token) = &args.token {
        config.credentials = cfrs::config::parse_token(token)?;
    }
    config.ingress = Ingress::new().catch_all(Service::Static {
        root: args.dir.clone(),
        spa: args.spa,
    });
    config = args.common.apply(config)?;
    run_tunnel(config, args.common.qr, args.common.run_for, vec![]).await
}

async fn share(args: ShareArgs) -> Result<()> {
    let mut share_config = match args.mode {
        ModeArg::Upload => {
            let dir = args.dir.clone().unwrap_or_else(default_upload_dir);
            ShareConfig::upload(dir)
        }
        ModeArg::Download => {
            let file = args
                .file
                .clone()
                .context("download mode needs --file")?;
            ShareConfig::download(file)
        }
        ModeArg::Proxy => {
            let port = args.port.context("proxy mode needs --port")?;
            cfrs::ports::confirm_local_http(port).await?;
            ShareConfig::proxy(format!("127.0.0.1:{port}"))
        }
    };
    if args.password || matches!(args.mode, ModeArg::Proxy) {
        share_config.gate = Gate::pin();
    }
    share_config.stop_after = args.stop_after;

    let mut config = Config::default();
    if let Some(token) = &args.token {
        config.credentials = cfrs::config::parse_token(token)?;
    }
    config.ingress = Ingress::new().catch_all(Service::Share(share_config.clone()));
    config = args.common.apply(config)?;

    let pin = share_config.gate.pin_display().map(str::to_string);
    let path = share_config.url_path();
    let controls_hint = args.idle_secs;
    run_share(
        config,
        args.common.qr,
        args.common.run_for,
        pin,
        path,
        controls_hint,
    )
    .await
}

async fn demo(args: DemoArgs) -> Result<()> {
    let mut config = Config::default();
    if let Some(token) = &args.token {
        config.credentials = cfrs::config::parse_token(token)?;
    }
    config.ingress = Ingress::new().catch_all(Service::HelloWorld);
    config = args.common.apply(config)?;
    let exit_on_verify = args.exit_on_verify;
    run_demo(config, args.common.qr, args.common.run_for, exit_on_verify).await
}

fn default_upload_dir() -> PathBuf {
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
    let downloads = home.join("Downloads");
    if downloads.is_dir() {
        downloads.join("cfrs")
    } else {
        home.join("cfrs-uploads")
    }
}

async fn run_tunnel(
    config: Config,
    qr: bool,
    run_for: Option<u64>,
    controls: Vec<Arc<ShareControl>>,
) -> Result<()> {
    let verify = config.verify;
    let handle = Tunnel::builder().config(config).build()?.start().await?;
    announce(&handle, qr)?;
    if verify {
        handle.verify(None).await?;
    }
    wait(run_for, controls).await;
    handle.shutdown().await;
    Ok(())
}

async fn run_share(
    config: Config,
    qr: bool,
    run_for: Option<u64>,
    pin: Option<String>,
    path: String,
    idle_secs: u64,
) -> Result<()> {
    let verify = config.verify;
    let handle = Tunnel::builder().config(config).build()?.start().await?;
    let base = handle.url().unwrap_or("https://<your-named-tunnel-hostname>").to_string();
    let public = format!("{}{}", base.trim_end_matches('/'), path);
    println!();
    println!("  cfrs: session  {public}");
    if let Some(pin) = &pin {
        println!("  cfrs: PIN      {pin}");
    }
    println!("  cfrs: edge     {}", handle.locations().join(", "));
    println!();
    if qr {
        print!("{}", cfrs::qr::render_terminal(&public)?);
    }
    if verify && handle.url().is_some() {
        handle.verify_url(&public, None).await?;
    }
    let controls = handle.share_controls();
    wait_with_idle(run_for, controls, idle_secs).await;
    handle.shutdown().await;
    Ok(())
}

async fn run_demo(
    config: Config,
    qr: bool,
    run_for: Option<u64>,
    exit_on_verify: bool,
) -> Result<()> {
    let handle = Tunnel::builder().config(config).build()?.start().await?;
    announce(&handle, qr)?;
    if exit_on_verify {
        handle.verify(Some("Hello, world! (cfrs)")).await?;
        println!("  cfrs: PROOF   {} -> HTTP 200 (built-in hello world)", handle.url().unwrap_or(""));
        handle.shutdown().await;
        return Ok(());
    }
    handle.verify(Some("Hello, world! (cfrs)")).await?;
    wait(run_for, vec![]).await;
    handle.shutdown().await;
    Ok(())
}

fn announce(handle: &cfrs::TunnelHandle, qr: bool) -> Result<()> {
    println!();
    match handle.url() {
        Some(url) => println!("  cfrs: public   {url}"),
        None => println!("  cfrs: tunnel   {} (named; hostname configured in Cloudflare)", handle.tunnel_id()),
    }
    println!("  cfrs: edge     {}", handle.locations().join(", "));
    println!();
    if qr {
        if let Some(url) = handle.url() {
            print!("{}", cfrs::qr::render_terminal(url)?);
        }
    }
    Ok(())
}

async fn wait(run_for: Option<u64>, controls: Vec<Arc<ShareControl>>) -> () {
    let stop_controls = async move {
        if controls.is_empty() {
            std::future::pending::<()>().await;
        }
        let mut set = tokio::task::JoinSet::new();
        for control in controls {
            set.spawn(async move { control.wait_stop().await });
        }
        let _ = set.join_next().await;
    };
    match run_for {
        Some(secs) => {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(secs)) => {}
                _ = tokio::signal::ctrl_c() => {}
                _ = stop_controls => {}
            }
        }
        None => {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = stop_controls => {}
            }
        }
    }
}

async fn wait_with_idle(
    run_for: Option<u64>,
    controls: Vec<Arc<ShareControl>>,
    idle_secs: u64,
) {
    let idle = (idle_secs > 0).then(|| Duration::from_secs(idle_secs));
    let watch = {
        let controls = controls.clone();
        async move {
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                if let Some(idle) = idle {
                    if controls.iter().any(|c| c.idle_for() >= idle) {
                        return;
                    }
                }
            }
        }
    };
    match run_for {
        Some(secs) => {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(secs)) => {}
                _ = tokio::signal::ctrl_c() => {}
                _ = wait_controls(controls) => {}
                _ = watch => {}
            }
        }
        None => {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = wait_controls(controls) => {}
                _ = watch => {}
            }
        }
    }
}

async fn wait_controls(controls: Vec<Arc<ShareControl>>) {
    if controls.is_empty() {
        std::future::pending::<()>().await;
    }
    let mut set = tokio::task::JoinSet::new();
    for control in controls {
        set.spawn(async move { control.wait_stop().await });
    }
    let _ = set.join_next().await;
}

// Keep ShareMode referenced for future CLI flags.
#[allow(dead_code)]
fn _mode(mode: ShareMode) -> ShareMode {
    mode
}
