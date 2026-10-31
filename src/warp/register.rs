//! Anonymous Cloudflare WARP registration.
//!
//! Two calls, both credential-free on the first one:
//!
//! 1. `POST /{version}/reg` — create a device. The body carries a throwaway
//!    X25519 public key so the service accepts it; the matching private half is
//!    discarded because MASQUE does not use it.
//! 2. `PATCH /{version}/reg/{id}` — enrol a P-256 public key (X.509 SPKI, base64)
//!    and switch the device from `wireguard` to `masque`. This is what makes the
//!    returned `config.peers[0].endpoint` point at the MASQUE front door and what
//!    lets the TLS client certificate authenticate the tunnel.
//!
//! Nothing here shells out to `wgcf`, `warp-cli` or `cloudflared`: the two HTTP
//! calls and the key generation are the whole of it.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// API host. Reachable on TCP 443, which is the point of this module.
pub const API_BASE: &str = "https://api.cloudflareclient.com";

/// API version segment. It must agree with the build number in
/// [`CLIENT_VERSION`]; the service rejects a mismatched pair.
pub const API_VERSION: &str = "v0a5641";

/// `CF-Client-Version` header value.
pub const CLIENT_VERSION: &str = "a-6.38.9-5641";

/// `User-Agent` the Android client sends, and the one the service expects.
pub const USER_AGENT: &str = "WARP for Android";

/// SNI the MASQUE front door presents.
pub const MASQUE_SNI: &str = "consumer-masque.cloudflareclient.com";

/// Default MASQUE port. 443 everywhere; the API may advertise others.
pub const MASQUE_PORT: u16 = 443;

/// The `:authority` of the CONNECT-IP request. Only the host matters; Cloudflare
/// uses it as a routing hint, not a real endpoint.
pub const CONNECT_URI: &str = "https://cloudflareaccess.com";

/// The device as the API reports it.
///
/// `Serialize` is not for the wire (the API only takes the two bodies below);
/// it exists so a caller can persist a registered device and resume it without
/// registering a second one.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Device {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub key_type: String,
    #[serde(default)]
    pub tunnel_type: String,
    pub account: Account,
    pub config: DeviceConfig,
    /// Only present on the `POST /reg` response.
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub warp_enabled: bool,
    #[serde(default)]
    pub waitlist_enabled: bool,
    #[serde(default)]
    pub policy: Policy,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Account {
    pub id: String,
    #[serde(default)]
    pub account_type: String,
    #[serde(default)]
    pub license: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeviceConfig {
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub peers: Vec<Peer>,
    #[serde(default)]
    pub interface: Interface,
    #[serde(default)]
    pub services: Services,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Peer {
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub endpoint: Endpoint,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Endpoint {
    #[serde(default)]
    pub v4: String,
    #[serde(default)]
    pub v6: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub ports: Vec<u16>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Interface {
    #[serde(default)]
    pub addresses: Addresses,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Addresses {
    #[serde(default)]
    pub v4: String,
    #[serde(default)]
    pub v6: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Services {
    #[serde(default)]
    pub http_proxy: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Policy {
    #[serde(default)]
    pub tunnel_protocol: String,
    #[serde(default)]
    pub post_quantum: String,
}

/// The `POST /reg` body. All values are strings, matching the Android client.
#[derive(Debug, Serialize)]
struct RegistrationRequest {
    key: String,
    install_id: String,
    fcm_token: String,
    tos: String,
    model: String,
    serial_number: String,
    os_version: String,
    key_type: String,
    tunnel_type: String,
    locale: String,
}

/// The `PATCH /reg/{id}` body that enrols a MASQUE key.
#[derive(Debug, Serialize)]
struct EnrolRequest {
    key: String,
    key_type: String,
    tunnel_type: String,
}

fn now_rfc3339_millis() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let millis = now.subsec_millis();
    let (y, mo, d, h, mi, s) = civil_from_unix(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{millis:03}Z")
}

/// Convert Unix seconds to a civil UTC date, so the crate needs no time library.
fn civil_from_unix(secs: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d, h as u32, mi as u32, s as u32)
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).expect("OS entropy unavailable");
    out
}

fn random_hex(n: usize) -> String {
    let mut out = String::with_capacity(n * 2);
    let bytes = random_bytes::<32>();
    for b in bytes.iter().take(n) {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn b64(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn client(bearer: Option<&str>) -> Result<reqwest::Client> {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::USER_AGENT,
        reqwest::header::HeaderValue::from_static(USER_AGENT),
    );
    headers.insert(
        "CF-Client-Version",
        reqwest::header::HeaderValue::from_static(CLIENT_VERSION),
    );
    headers.insert(
        reqwest::header::CONTENT_TYPE,
        reqwest::header::HeaderValue::from_static("application/json; charset=UTF-8"),
    );
    headers.insert(
        reqwest::header::CONNECTION,
        reqwest::header::HeaderValue::from_static("Keep-Alive"),
    );
    if let Some(token) = bearer {
        let value = format!("Bearer {token}");
        headers.insert(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_str(&value)?,
        );
    }
    Ok(reqwest::Client::builder()
        .default_headers(headers)
        .timeout(std::time::Duration::from_secs(30))
        .build()?)
}

async fn check(resp: reqwest::Response) -> Result<Device> {
    let status = resp.status();
    let body = resp.text().await.context("reading WARP API body")?;
    if !status.is_success() {
        bail!("WARP API answered {status}: {body}");
    }
    serde_json::from_str(&body).with_context(|| format!("decoding WARP API body: {body}"))
}

/// Create an anonymous device. Returns the device plus its bearer token, which
/// is needed for the enrolment call and for later account queries.
pub async fn create_device() -> Result<Device> {
    let body = RegistrationRequest {
        // A throwaway X25519 public key. The API validates its shape, not that
        // anybody holds the private half, and MASQUE never uses it.
        key: b64(&random_bytes::<32>()),
        install_id: String::new(),
        fcm_token: String::new(),
        tos: now_rfc3339_millis(),
        model: "PC".into(),
        serial_number: random_hex(8),
        os_version: String::new(),
        key_type: "curve25519".into(),
        tunnel_type: "wireguard".into(),
        locale: "en_US".into(),
    };
    let resp = client(None)?
        .post(format!("{API_BASE}/{API_VERSION}/reg"))
        .json(&body)
        .send()
        .await
        .context("POST /reg")?;
    check(resp).await
}

/// Enrol a MASQUE identity: upload the P-256 public key (X.509 SPKI, base64) and
/// switch the device to the `masque` tunnel type.
pub async fn enrol_masque(device_id: &str, token: &str, spki_b64: &str) -> Result<Device> {
    let body = EnrolRequest {
        key: spki_b64.to_string(),
        key_type: "secp256r1".into(),
        tunnel_type: "masque".into(),
    };
    let resp = client(Some(token))?
        .patch(format!("{API_BASE}/{API_VERSION}/reg/{device_id}"))
        .json(&body)
        .send()
        .await
        .context("PATCH /reg/{id}")?;
    check(resp).await
}

impl Device {
    /// IPv4 address the tunnel assigned, without any prefix length.
    pub fn ipv4(&self) -> Option<std::net::Ipv4Addr> {
        let raw = self.config.interface.addresses.v4.trim();
        let raw = raw.split('/').next().unwrap_or(raw);
        raw.parse().ok()
    }

    /// IPv6 address the tunnel assigned, without any prefix length.
    pub fn ipv6(&self) -> Option<std::net::Ipv6Addr> {
        let raw = self.config.interface.addresses.v6.trim();
        let raw = raw.split('/').next().unwrap_or(raw);
        raw.parse().ok()
    }

    /// The MASQUE front door, as an address to dial.
    pub fn masque_endpoint(&self) -> Option<std::net::SocketAddr> {
        let peer = self.config.peers.first()?;
        let v4 = peer.endpoint.v4.split(':').next().unwrap_or("").trim();
        if let Ok(ip) = v4.parse::<std::net::Ipv4Addr>() {
            return Some(std::net::SocketAddr::new(ip.into(), MASQUE_PORT));
        }
        let v6 = peer.endpoint.v6.trim().trim_start_matches('[');
        let v6 = v6.split(']').next().unwrap_or(v6);
        if let Ok(ip) = v6.parse::<std::net::Ipv6Addr>() {
            return Some(std::net::SocketAddr::new(ip.into(), MASQUE_PORT));
        }
        None
    }

    /// The server's pinned public key, PEM (`PUBLIC KEY`).
    pub fn peer_public_key_pem(&self) -> Option<&str> {
        self.config
            .peers
            .first()
            .map(|p| p.public_key.as_str())
            .filter(|k| k.contains("BEGIN PUBLIC KEY"))
    }

    /// The `client_id`, whose first three base64 bytes are the WireGuard
    /// "reserved" tag. Kept because the WireGuard mode needs it.
    pub fn reserved(&self) -> Option<[u8; 3]> {
        use base64::Engine;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(self.config.client_id.as_bytes())
            .ok()?;
        if raw.len() < 3 {
            return None;
        }
        Some([raw[0], raw[1], raw[2]])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_dates_are_right() {
        assert_eq!(civil_from_unix(0), (1970, 1, 1, 0, 0, 0));
        // 2026-10-31T00:00:00Z
        assert_eq!(civil_from_unix(1_793_404_800), (2026, 10, 31, 0, 0, 0));
    }

    #[test]
    fn timestamp_shape() {
        let ts = now_rfc3339_millis();
        assert_eq!(ts.len(), 24, "{ts}");
        assert!(ts.ends_with('Z'));
        assert_eq!(&ts[4..5], "-");
    }

    #[test]
    fn endpoint_parsing_strips_the_zero_port() {
        let device: Device = serde_json::from_str(
            r#"{"id":"x","account":{"id":"a"},"config":{"peers":[{"public_key":"k",
                "endpoint":{"v4":"162.159.198.2:0","v6":"[2606:4700:103::2]:0"}}],
                "interface":{"addresses":{"v4":"172.16.0.2","v6":"2606:4700:110::1"}}}}"#,
        )
        .unwrap();
        assert_eq!(
            device.masque_endpoint(),
            Some("162.159.198.2:443".parse().unwrap())
        );
        assert_eq!(device.ipv4(), Some("172.16.0.2".parse().unwrap()));
        assert_eq!(device.ipv6(), Some("2606:4700:110::1".parse().unwrap()));
    }
}
