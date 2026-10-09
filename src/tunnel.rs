//! The tunnel engine: credentials, edge registration, HA reactors, reconnect
//! and dispatch to the service runtime.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use cloudflare_quick_tunnel::edge::IpVersionFilter;
use cloudflare_quick_tunnel::{api, edge, quic_dial, rpc};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{info, warn};
use uuid::Uuid;

use crate::config::{parse_credentials_file, parse_token, Config, Credentials, Protocol, ReconnectPolicy};
use crate::ingress::{Ingress, Service};
use crate::metrics::Metrics;
use crate::proxy;
use crate::service::ServiceRuntime;
use crate::share::ShareControl;
use crate::util::validate_quick_hostname;

pub const CLIENT_VERSION: &str = concat!("cfrs/", env!("CARGO_PKG_VERSION"));
const REGISTER_TIMEOUT: Duration = Duration::from_secs(30);
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// Fluent builder for a [`Tunnel`].
pub struct TunnelBuilder {
    config: Config,
}

impl TunnelBuilder {
    pub fn quick() -> Self {
        Self {
            config: Config::default(),
        }
    }

    pub fn token(token: impl Into<String>) -> Result<Self> {
        Ok(Self {
            config: Config {
                credentials: parse_token(&token.into())?,
                ..Config::default()
            },
        })
    }

    pub fn credentials_file(path: impl Into<std::path::PathBuf>) -> Result<Self> {
        Ok(Self {
            config: Config {
                credentials: parse_credentials_file(&path.into())?,
                ..Config::default()
            },
        })
    }

    pub fn credentials(mut self, credentials: Credentials) -> Self {
        self.config.credentials = credentials;
        self
    }

    pub fn config(mut self, config: Config) -> Self {
        self.config = config;
        self
    }

    pub fn service(mut self, service: Service) -> Self {
        self.config.ingress = Ingress::default().catch_all(service);
        self
    }

    pub fn ingress(mut self, ingress: Ingress) -> Self {
        self.config.ingress = ingress;
        self
    }

    pub fn ha_connections(mut self, count: u8) -> Self {
        self.config.ha_connections = count.clamp(1, 8);
        self
    }

    pub fn protocol(mut self, protocol: Protocol) -> Self {
        self.config.protocol = protocol;
        self
    }

    pub fn reconnect(mut self, policy: ReconnectPolicy) -> Self {
        self.config.reconnect = policy;
        self
    }

    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.config.user_agent = user_agent.into();
        self
    }

    pub fn service_url(mut self, url: impl Into<String>) -> Self {
        self.config.service_url = url.into();
        self
    }

    pub fn verify(mut self, yes: bool) -> Self {
        self.config.verify = yes;
        self
    }

    pub fn build(self) -> Result<Tunnel> {
        if self.config.ingress.is_empty() {
            bail!("no ingress rules configured");
        }
        Ok(Tunnel {
            config: self.config,
        })
    }
}

pub struct Tunnel {
    config: Config,
}

impl Tunnel {
    pub fn builder() -> TunnelBuilder {
        TunnelBuilder::quick()
    }

    pub fn quick() -> TunnelBuilder {
        TunnelBuilder::quick()
    }

    pub fn token(token: impl Into<String>) -> Result<TunnelBuilder> {
        TunnelBuilder::token(token)
    }

    /// Provision/load credentials, register with the edge and start serving.
    pub async fn start(self) -> Result<TunnelHandle> {
        crate::init_crypto();
        let Config {
            service_url,
            user_agent,
            credentials,
            protocol,
            ha_connections,
            reconnect,
            ingress,
            verify,
        } = self.config;

        if protocol.resolved() == Protocol::Http2 {
            bail!("the http2 edge transport is not implemented yet; use quic or auto");
        }

        let (auth, tunnel_id, public_url) =
            resolve_credentials(&credentials, &service_url, &user_agent).await?;
        let account_tag = auth.account_tag.clone();

        let metrics = Metrics::new();
        let runtime = Arc::new(ServiceRuntime::build(&ingress, metrics.clone())?);
        let ingress = Arc::new(ingress);

        let endpoint = quic_dial::build_endpoint()?;
        let (conn, control, location) =
            connect_once(&endpoint, &auth, tunnel_id, 0, false).await?;
        metrics.connection_opened();

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut tasks = Vec::new();
        let locations = vec![location.clone()];

        // First reactor (conn_index 0) is already connected.
        tasks.push(tokio::spawn(reactor(
            runtime.clone(),
            ingress.clone(),
            auth.clone(),
            tunnel_id,
            endpoint.clone(),
            conn,
            control,
            metrics.clone(),
            shutdown_rx.clone(),
            reconnect.clone(),
            0,
        )));

        // Remaining HA legs register in the background.
        for index in 1..ha_connections {
            let runtime = runtime.clone();
            let ingress = ingress.clone();
            let auth = auth.clone();
            let endpoint = endpoint.clone();
            let metrics = metrics.clone();
            let shutdown_rx = shutdown_rx.clone();
            let reconnect = reconnect.clone();
            tasks.push(tokio::spawn(async move {
                match connect_once(&endpoint, &auth, tunnel_id, index, false).await {
                    Ok((conn, control, location)) => {
                        metrics.connection_opened();
                        info!(conn_index = index, %location, "HA leg registered");
                        reactor(
                            runtime,
                            ingress,
                            auth,
                            tunnel_id,
                            endpoint,
                            conn,
                            control,
                            metrics,
                            shutdown_rx,
                            reconnect,
                            index,
                        )
                        .await;
                    }
                    Err(err) => {
                        warn!(conn_index = index, error = %err, "HA leg failed to register");
                    }
                }
            }));
        }

        Ok(TunnelHandle {
            url: public_url,
            tunnel_id,
            account_tag,
            locations,
            metrics,
            runtime,
            shutdown: shutdown_tx,
            tasks,
            verify,
        })
    }
}

async fn resolve_credentials(
    credentials: &Credentials,
    service_url: &str,
    user_agent: &str,
) -> Result<(rpc::TunnelAuth, Uuid, Option<String>)> {
    match credentials {
        Credentials::Quick => {
            let tunnel = api::request_tunnel(service_url, user_agent)
                .await
                .context("provisioning quick tunnel")?;
            let url = validate_quick_hostname(&tunnel.hostname)?;
            let tunnel_id = Uuid::parse_str(&tunnel.id).context("quick tunnel id is not a UUID")?;
            Ok((
                rpc::TunnelAuth {
                    account_tag: tunnel.account_tag,
                    tunnel_secret: tunnel.secret,
                },
                tunnel_id,
                Some(url),
            ))
        }
        Credentials::Token(token) => {
            let (auth, tunnel_id) = split_explicit(parse_token(token)?)?;
            Ok((auth, tunnel_id, None))
        }
        Credentials::File(path) => {
            let (auth, tunnel_id) = split_explicit(parse_credentials_file(path)?)?;
            Ok((auth, tunnel_id, None))
        }
        Credentials::Explicit {
            account_tag,
            tunnel_id,
            secret,
        } => Ok((
            rpc::TunnelAuth {
                account_tag: account_tag.clone(),
                tunnel_secret: secret.clone(),
            },
            *tunnel_id,
            None,
        )),
    }
}

fn split_explicit(credentials: Credentials) -> Result<(rpc::TunnelAuth, Uuid)> {
    match credentials {
        Credentials::Explicit {
            account_tag,
            tunnel_id,
            secret,
        } => Ok((
            rpc::TunnelAuth {
                account_tag,
                tunnel_secret: secret,
            },
            tunnel_id,
        )),
        _ => bail!("expected explicit credentials"),
    }
}

async fn connect_once(
    endpoint: &quinn::Endpoint,
    auth: &rpc::TunnelAuth,
    tunnel_id: Uuid,
    conn_index: u8,
    replace_existing: bool,
) -> Result<(quinn::Connection, rpc::ControlSession, String)> {
    let edges = edge::discover(IpVersionFilter::Auto)
        .await
        .context("edge discovery")?;
    if edges.is_empty() {
        bail!("edge discovery returned no addresses");
    }
    let candidates = edges.len().min(5);
    let conn = quic_dial::dial_any(endpoint, &edges[..candidates])
        .await
        .context("QUIC handshake with the Cloudflare edge")?;

    let mut options = rpc::ConnectionOptions::default_for_quick_tunnel(CLIENT_VERSION);
    options.replace_existing = replace_existing;

    let (details, control) = tokio::time::timeout(
        REGISTER_TIMEOUT,
        rpc::register_connection(&conn, auth, tunnel_id, conn_index, &options),
    )
    .await
    .map_err(|_| anyhow::anyhow!("register_connection timed out"))??;
    Ok((conn, control, details.location))
}

#[allow(clippy::too_many_arguments)]
async fn reactor(
    runtime: Arc<ServiceRuntime>,
    ingress: Arc<Ingress>,
    auth: rpc::TunnelAuth,
    tunnel_id: Uuid,
    endpoint: quinn::Endpoint,
    mut conn: quinn::Connection,
    mut control: rpc::ControlSession,
    metrics: Metrics,
    mut shutdown: watch::Receiver<bool>,
    policy: ReconnectPolicy,
    conn_index: u8,
) {
    loop {
        if *shutdown.borrow() {
            control.shutdown_graceful(SHUTDOWN_GRACE).await;
            return;
        }
        let lost = tokio::select! {
            biased;
            _ = shutdown.changed() => {
                control.shutdown_graceful(SHUTDOWN_GRACE).await;
                return;
            }
            accepted = conn.accept_bi() => {
                match accepted {
                    Ok((send, recv)) => {
                        let runtime = runtime.clone();
                        let ingress = ingress.clone();
                        tokio::spawn(async move {
                            proxy::serve_stream(runtime, ingress, send, recv).await;
                        });
                        false
                    }
                    Err(err) => {
                        warn!(conn_index, error = %err, "edge closed the connection");
                        true
                    }
                }
            }
        };
        if !lost {
            continue;
        }

        drop(control);
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            if attempt > policy.max_attempts {
                warn!(conn_index, "giving up after {} reconnect attempts", policy.max_attempts);
                return;
            }
            let delay = policy.backoff(attempt);
            let mut wait = shutdown.clone();
            tokio::select! {
                biased;
                _ = wait.changed() => {
                    return;
                }
                _ = tokio::time::sleep(delay) => {}
            }
            match connect_once(&endpoint, &auth, tunnel_id, conn_index, true).await {
                Ok((new_conn, new_control, location)) => {
                    info!(conn_index, attempt, %location, "reconnected");
                    metrics.reconnect();
                    metrics.connection_opened();
                    conn = new_conn;
                    control = new_control;
                    break;
                }
                Err(err) => {
                    warn!(conn_index, attempt, error = %err, "reconnect failed");
                    metrics.error();
                }
            }
        }
    }
}

/// A running tunnel.
pub struct TunnelHandle {
    url: Option<String>,
    tunnel_id: Uuid,
    account_tag: String,
    locations: Vec<String>,
    metrics: Metrics,
    runtime: Arc<ServiceRuntime>,
    shutdown: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
    verify: bool,
}

impl TunnelHandle {
    /// Public URL for a quick tunnel; `None` for a named tunnel (the hostname
    /// is configured in the Cloudflare dashboard).
    pub fn url(&self) -> Option<&str> {
        self.url.as_deref()
    }

    pub fn tunnel_id(&self) -> Uuid {
        self.tunnel_id
    }

    pub fn account_tag(&self) -> &str {
        &self.account_tag
    }

    pub fn locations(&self) -> &[String] {
        &self.locations
    }

    pub fn metrics(&self) -> Metrics {
        self.metrics.clone()
    }

    pub fn share_controls(&self) -> Vec<Arc<ShareControl>> {
        self.runtime.share_controls()
    }

    /// Fetch the public URL and confirm the tunnel is reachable. For quick
    /// tunnels the expected token may be checked against the body.
    pub async fn verify(&self, expected: Option<&str>) -> Result<()> {
        let Some(url) = self.url.as_deref() else {
            return Ok(());
        };
        self.verify_url(url, expected).await
    }

    /// Like [`verify`](Self::verify) but for a specific path on the public
    /// URL (a share session lives under `/s/<token>/`, not at the root).
    pub async fn verify_url(&self, url: &str, expected: Option<&str>) -> Result<()> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()?;
        let mut last = String::from("no attempt");
        for attempt in 1..=20 {
            match client.get(url).send().await {
                Ok(response) => {
                    let status = response.status();
                    let body = response.text().await.unwrap_or_default();
                    let ok = status.is_success()
                        && expected.map(|token| body.contains(token)).unwrap_or(true);
                    if ok {
                        info!(%url, status = status.as_u16(), "verified public URL");
                        return Ok(());
                    }
                    last = format!("HTTP {}", status.as_u16());
                }
                Err(err) => last = err.to_string(),
            }
            tracing::debug!(attempt, %last, "verification retry");
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        bail!("could not verify {url}: {last}")
    }

    pub fn wants_verify(&self) -> bool {
        self.verify
    }

    /// Signal every reactor and wait for them to drain.
    pub async fn shutdown(mut self) {
        let _ = self.shutdown.send(true);
        let tasks = std::mem::take(&mut self.tasks);
        for task in tasks {
            let _ = tokio::time::timeout(SHUTDOWN_GRACE + Duration::from_secs(2), task).await;
        }
    }
}

impl Drop for TunnelHandle {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
    }
}
