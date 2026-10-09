//! Ingress: which local service answers which public hostname/path.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Result};
use serde::Deserialize;

use crate::share::ShareConfig;

/// A local service the tunnel can expose.
#[derive(Clone, Debug)]
pub enum Service {
    /// An `http://` or `https://` origin.
    Http(String),
    /// An HTTP origin on a filesystem socket.
    Unix(PathBuf),
    /// An HTTPS origin on a filesystem socket.
    UnixTls(PathBuf),
    /// A raw TCP origin (`tcp://host:port`), proxied byte-for-byte.
    Tcp(String),
    /// cloudflared's built-in hello world.
    HelloWorld,
    /// A fixed status code.
    Status(u16),
    /// A directory served from disk (a `spa` fallback serves index.html).
    Static { root: PathBuf, spa: bool },
    /// Prometheus metrics for this tunnel.
    Metrics,
    /// Upload / download / proxy session (the quickbridge feature set).
    Share(ShareConfig),
}

impl Service {
    /// Parse a cloudflared-style service string, plus cfrs extensions
    /// (`static:` / `spa:` / `metrics`).
    pub fn parse(value: &str) -> Result<Self> {
        let value = value.trim();
        if let Some(rest) = value.strip_prefix("http://") {
            return Ok(Service::Http(format!("http://{rest}")));
        }
        if let Some(rest) = value.strip_prefix("https://") {
            return Ok(Service::Http(format!("https://{rest}")));
        }
        if let Some(rest) = value.strip_prefix("unix+tls:") {
            return Ok(Service::UnixTls(PathBuf::from(rest)));
        }
        if let Some(rest) = value.strip_prefix("unix:") {
            return Ok(Service::Unix(PathBuf::from(rest)));
        }
        if let Some(rest) = value.strip_prefix("tcp://") {
            return Ok(Service::Tcp(rest.to_string()));
        }
        if let Some(rest) = value.strip_prefix("static:") {
            return Ok(Service::Static {
                root: PathBuf::from(rest),
                spa: false,
            });
        }
        if let Some(rest) = value.strip_prefix("spa:") {
            return Ok(Service::Static {
                root: PathBuf::from(rest),
                spa: true,
            });
        }
        if let Some(rest) = value.strip_prefix("http_status:") {
            let code: u16 = rest.parse().map_err(|_| anyhow::anyhow!("bad status {rest}"))?;
            if !(100..=999).contains(&code) {
                bail!("status out of range: {code}");
            }
            return Ok(Service::Status(code));
        }
        match value {
            "hello_world" => Ok(Service::HelloWorld),
            "metrics" => Ok(Service::Metrics),
            other => bail!("unsupported service {other:?}"),
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Service::Http(url) => url.clone(),
            Service::Unix(path) => format!("unix:{}", path.display()),
            Service::UnixTls(path) => format!("unix+tls:{}", path.display()),
            Service::Tcp(addr) => format!("tcp://{addr}"),
            Service::HelloWorld => "hello_world".into(),
            Service::Status(code) => format!("http_status:{code}"),
            Service::Static { root, spa } => {
                format!("{}:{}", if *spa { "spa" } else { "static" }, root.display())
            }
            Service::Metrics => "metrics".into(),
            Service::Share(config) => config.describe(),
        }
    }

    /// Raw-TCP services bypass the HTTP layer entirely.
    pub fn is_tcp(&self) -> bool {
        matches!(self, Service::Tcp(_))
    }
}

/// Per-rule origin tuning, mirroring the useful subset of cloudflared's
/// `originRequest`.
#[derive(Clone, Debug, Default)]
pub struct OriginOptions {
    pub no_tls_verify: bool,
    pub http_host_header: Option<String>,
    pub connect_timeout: Option<Duration>,
    pub tls_timeout: Option<Duration>,
    pub keep_alive_timeout: Option<Duration>,
    pub disable_chunked_encoding: bool,
}

#[derive(Clone, Debug)]
pub struct IngressRule {
    pub hostname: Option<String>,
    pub path: Option<String>,
    pub service: Service,
    pub origin: OriginOptions,
}

impl IngressRule {
    pub fn catch_all(service: Service) -> Self {
        Self {
            hostname: None,
            path: None,
            service,
            origin: OriginOptions::default(),
        }
    }

    fn matches(&self, hostname: &str, path: &str) -> bool {
        if let Some(pattern) = &self.hostname {
            if !hostname_matches(pattern, hostname) {
                return false;
            }
        }
        if let Some(prefix) = &self.path {
            if !path.starts_with(prefix.as_str()) {
                return false;
            }
        }
        true
    }
}

fn hostname_matches(pattern: &str, hostname: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let hostname = hostname.to_ascii_lowercase();
    if let Some(suffix) = pattern.strip_prefix("*.") {
        if hostname == suffix {
            return true;
        }
        // A wildcard matches exactly one label, so `a.b.example.com` is not
        // covered by `*.example.com`.
        return match hostname.strip_suffix(suffix) {
            Some(prefix) => match prefix.strip_suffix('.') {
                Some(label) => !label.is_empty() && !label.contains('.'),
                None => false,
            },
            None => false,
        };
    }
    pattern == hostname
}

/// An ordered rule set. The last rule is normally a catch-all.
#[derive(Clone, Debug, Default)]
pub struct Ingress {
    pub rules: Vec<IngressRule>,
}

impl Ingress {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn rule(mut self, hostname: impl Into<String>, path: Option<&str>, service: Service) -> Self {
        self.rules.push(IngressRule {
            hostname: Some(hostname.into()),
            path: path.map(str::to_string),
            service,
            origin: OriginOptions::default(),
        });
        self
    }

    pub fn rule_with(mut self, rule: IngressRule) -> Self {
        self.rules.push(rule);
        self
    }

    pub fn catch_all(mut self, service: Service) -> Self {
        self.rules.push(IngressRule::catch_all(service));
        self
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// First matching rule for a request, in declaration order.
    pub fn resolve(&self, hostname: &str, path: &str) -> Option<&IngressRule> {
        self.rules.iter().find(|rule| rule.matches(hostname, path))
    }

    /// Index of the first matching rule.
    pub fn resolve_index(&self, hostname: &str, path: &str) -> Option<usize> {
        self.rules.iter().position(|rule| rule.matches(hostname, path))
    }
}

// ── YAML parsing (cloudflared-compatible subset) ─────────────────────────────

#[derive(Deserialize)]
pub(crate) struct RawIngress {
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub service: String,
    #[serde(default, rename = "originRequest")]
    pub origin_request: RawOriginOptions,
}

#[derive(Deserialize, Default)]
pub(crate) struct RawOriginOptions {
    #[serde(default, rename = "noTLSVerify")]
    pub no_tls_verify: bool,
    #[serde(default, rename = "httpHostHeader")]
    pub http_host_header: Option<String>,
    #[serde(default, rename = "connectTimeout")]
    pub connect_timeout: Option<String>,
    #[serde(default, rename = "tlsTimeout")]
    pub tls_timeout: Option<String>,
    #[serde(default, rename = "keepAliveTimeout")]
    pub keep_alive_timeout: Option<String>,
    #[serde(default, rename = "disableChunkedEncoding")]
    pub disable_chunked_encoding: bool,
}

fn parse_duration(value: &Option<String>) -> Option<Duration> {
    let value = value.as_ref()?;
    humantime(value).ok()
}

/// Minimal `30s` / `1m` / `500ms` parser.
fn humantime(value: &str) -> Result<Duration> {
    let value = value.trim();
    let (number, unit) = value
        .char_indices()
        .find(|(_, c)| !c.is_ascii_digit())
        .map(|(i, _)| value.split_at(i))
        .unwrap_or((value, "s"));
    let number: f64 = number.parse().map_err(|_| anyhow::anyhow!("bad duration {value}"))?;
    let multiplier = match unit.trim() {
        "" | "s" => 1.0,
        "ms" => 0.001,
        "m" => 60.0,
        "h" => 3600.0,
        other => bail!("unknown duration unit {other:?}"),
    };
    Ok(Duration::from_secs_f64(number * multiplier))
}

impl RawOriginOptions {
    pub fn into_options(self) -> OriginOptions {
        OriginOptions {
            no_tls_verify: self.no_tls_verify,
            http_host_header: self.http_host_header,
            connect_timeout: parse_duration(&self.connect_timeout),
            tls_timeout: parse_duration(&self.tls_timeout),
            keep_alive_timeout: parse_duration(&self.keep_alive_timeout),
            disable_chunked_encoding: self.disable_chunked_encoding,
        }
    }
}

pub(crate) fn ingress_from_raw(rules: Vec<RawIngress>) -> Result<Ingress> {
    let mut ingress = Ingress::new();
    for raw in rules {
        let service = Service::parse(&raw.service)?;
        ingress.rules.push(IngressRule {
            hostname: raw.hostname,
            path: raw.path,
            service,
            origin: raw.origin_request.into_options(),
        });
    }
    Ok(ingress)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_services() {
        assert!(matches!(Service::parse("http://127.0.0.1:8080").unwrap(), Service::Http(_)));
        assert!(matches!(Service::parse("https://x:443").unwrap(), Service::Http(_)));
        assert!(matches!(Service::parse("unix:/run/x.sock").unwrap(), Service::Unix(_)));
        assert!(matches!(Service::parse("tcp://db:5432").unwrap(), Service::Tcp(_)));
        assert!(matches!(Service::parse("http_status:404").unwrap(), Service::Status(404)));
        assert!(matches!(Service::parse("static:/srv").unwrap(), Service::Static { spa: false, .. }));
        assert!(matches!(Service::parse("spa:/srv").unwrap(), Service::Static { spa: true, .. }));
        assert!(Service::parse("nope://x").is_err());
    }

    #[test]
    fn wildcard_hosts() {
        assert!(hostname_matches("*.example.com", "a.example.com"));
        assert!(hostname_matches("*.example.com", "example.com"));
        assert!(!hostname_matches("*.example.com", "a.b.example.com"));
        assert!(!hostname_matches("*.example.com", "example.org"));
        assert!(hostname_matches("app.example.com", "APP.example.com"));
    }

    #[test]
    fn resolves_first_match() {
        let ingress = Ingress::new()
            .rule("api.example.com", Some("/v1"), Service::HelloWorld)
            .rule("api.example.com", None, Service::Status(404))
            .catch_all(Service::Status(503));
        assert!(matches!(
            ingress.resolve("api.example.com", "/v1/x").unwrap().service,
            Service::HelloWorld
        ));
        assert!(matches!(
            ingress.resolve("api.example.com", "/other").unwrap().service,
            Service::Status(404)
        ));
        assert!(matches!(
            ingress.resolve("other.example.com", "/").unwrap().service,
            Service::Status(503)
        ));
    }

    #[test]
    fn durations() {
        assert_eq!(humantime("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(humantime("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(humantime("2m").unwrap(), Duration::from_secs(120));
        assert!(humantime("x").is_err());
    }
}
