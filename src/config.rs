//! Configuration: credentials, transport, ingress and reconnect policy.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use base64::Engine;
use serde::Deserialize;
use uuid::Uuid;

use crate::ingress::{Ingress, Service};

/// How to authenticate the tunnel with the edge.
#[derive(Clone, Debug)]
pub enum Credentials {
    /// Anonymous `trycloudflare.com` quick tunnel (provisioned on start).
    Quick,
    /// Named tunnel token: base64 of `{"a":account,"t":tunnel_id,"s":secret}`.
    Token(String),
    /// A cloudflared credentials JSON file.
    File(PathBuf),
    /// The three fields already decoded.
    Explicit {
        account_tag: String,
        tunnel_id: Uuid,
        secret: Vec<u8>,
    },
}

#[derive(Deserialize)]
struct TokenJson {
    a: String,
    t: String,
    s: String,
}

#[derive(Deserialize)]
struct CredentialsJson {
    #[serde(rename = "AccountTag", alias = "account_tag")]
    account_tag: String,
    #[serde(rename = "TunnelID", alias = "tunnel_id")]
    tunnel_id: String,
    #[serde(rename = "TunnelSecret", alias = "tunnel_secret")]
    tunnel_secret: String,
}

/// Decode a named-tunnel token. Cloudflare emits standard base64 of the JSON
/// envelope; the secret inside is base64 as well.
pub fn parse_token(token: &str) -> Result<Credentials> {
    let token = token.trim();
    let raw = decode_b64(token).context("token is not valid base64")?;
    let parsed: TokenJson = serde_json::from_slice(&raw).context("token payload is not JSON")?;
    let secret = decode_b64(&parsed.s)?;
    let tunnel_id = Uuid::parse_str(&parsed.t).context("token tunnel id is not a UUID")?;
    Ok(Credentials::Explicit {
        account_tag: parsed.a,
        tunnel_id,
        secret,
    })
}

/// Load a cloudflared credentials file.
pub fn parse_credentials_file(path: &std::path::Path) -> Result<Credentials> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading credentials file {}", path.display()))?;
    let parsed: CredentialsJson =
        serde_json::from_str(&text).context("credentials file is not JSON")?;
    let secret = decode_b64(&parsed.tunnel_secret).context("TunnelSecret is not base64")?;
    let tunnel_id = Uuid::parse_str(&parsed.tunnel_id).context("TunnelID is not a UUID")?;
    Ok(Credentials::Explicit {
        account_tag: parsed.account_tag,
        tunnel_id,
        secret,
    })
}

fn decode_b64(value: &str) -> Result<Vec<u8>> {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
    STANDARD
        .decode(value)
        .or_else(|_| URL_SAFE.decode(value))
        .or_else(|_| URL_SAFE_NO_PAD.decode(value))
        .map_err(|e| anyhow::anyhow!("base64: {e}"))
}

/// Edge transport. QUIC is implemented; HTTP/2 is accepted for compatibility
/// but currently returns a clear error at start.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Protocol {
    #[default]
    Auto,
    Quic,
    Http2,
}

impl Protocol {
    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "auto" => Ok(Protocol::Auto),
            "quic" => Ok(Protocol::Quic),
            "http2" | "h2" => Ok(Protocol::Http2),
            other => bail!("unknown protocol {other:?}; expected auto, quic or http2"),
        }
    }

    /// The transport actually used. `auto` prefers QUIC.
    pub fn resolved(self) -> Protocol {
        match self {
            Protocol::Auto => Protocol::Quic,
            other => other,
        }
    }
}

/// Reconnect behaviour when the edge drops a connection.
#[derive(Clone, Debug)]
pub struct ReconnectPolicy {
    pub max_attempts: u32,
    pub initial: Duration,
    pub max: Duration,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 10,
            initial: Duration::from_secs(1),
            max: Duration::from_secs(30),
        }
    }
}

impl ReconnectPolicy {
    pub fn backoff(&self, attempt: u32) -> Duration {
        let shift = attempt.saturating_sub(1).min(20);
        let secs = self.initial.as_secs().saturating_mul(1u64 << shift);
        Duration::from_secs(secs.min(self.max.as_secs()))
    }
}

/// Everything needed to run a tunnel.
#[derive(Clone, Debug)]
pub struct Config {
    pub service_url: String,
    pub user_agent: String,
    pub credentials: Credentials,
    pub protocol: Protocol,
    pub ha_connections: u8,
    pub reconnect: ReconnectPolicy,
    pub ingress: Ingress,
    pub verify: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            service_url: cloudflare_quick_tunnel::api::DEFAULT_SERVICE_URL.to_string(),
            user_agent: format!("cfrs/{}", env!("CARGO_PKG_VERSION")),
            credentials: Credentials::Quick,
            protocol: Protocol::Auto,
            ha_connections: 2,
            reconnect: ReconnectPolicy::default(),
            ingress: Ingress::default(),
            verify: false,
        }
    }
}

impl Config {
    /// A single catch-all HTTP service.
    pub fn with_service(service: Service) -> Self {
        Config {
            ingress: Ingress::default().catch_all(service),
            ..Config::default()
        }
    }
}

// ── cloudflared-compatible config file ──────────────────────────────────────

#[derive(Deserialize)]
struct RawConfig {
    #[serde(default)]
    tunnel: Option<String>,
    #[serde(default, rename = "credentials-file")]
    credentials_file: Option<PathBuf>,
    #[serde(default)]
    ingress: Vec<crate::ingress::RawIngress>,
    #[serde(default)]
    protocol: Option<String>,
    #[serde(default, rename = "ha-connections")]
    ha_connections: Option<u8>,
}

/// Load a cloudflared-style YAML config. `tunnel:` is treated as a named-tunnel
/// token when present; otherwise `credentials-file:` is read.
pub fn load_file(path: &std::path::Path) -> Result<Config> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading config {}", path.display()))?;
    let raw: RawConfig =
        serde_yaml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;

    let mut config = Config::default();
    if !raw.ingress.is_empty() {
        config.ingress = crate::ingress::ingress_from_raw(raw.ingress)?;
    }
    if let Some(token) = raw.tunnel {
        config.credentials = parse_token(&token)?;
    } else if let Some(file) = raw.credentials_file {
        config.credentials = parse_credentials_file(&file)?;
    }
    if let Some(protocol) = raw.protocol {
        config.protocol = Protocol::parse(&protocol)?;
    }
    if let Some(ha) = raw.ha_connections {
        config.ha_connections = ha.clamp(1, 8);
    }
    Ok(config)
}
