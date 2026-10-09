//! cfrs — expose anything on the public Electrosphere through Cloudflare
//! tunnels, from Rust.
//!
//! The crate is usable as a library:
//!
//! ```no_run
//! use cfrs::{Service, Tunnel};
//!
//! # async fn run() -> anyhow::Result<()> {
//! let handle = Tunnel::quick()
//!     .service(Service::parse("http://127.0.0.1:8080")?)
//!     .build()?
//!     .start()
//!     .await?;
//! println!("{:?}", handle.url());
//! handle.shutdown().await;
//! # Ok(())
//! # }
//! ```
//!
//! It speaks the Cloudflare quick-tunnel protocol natively (QUIC + Cap'n Proto
//! RPC, no `cloudflared` subprocess) and also accepts named-tunnel tokens.

pub mod config;
pub mod gate;
pub mod ingress;
pub mod metrics;
pub mod net;
pub mod ports;
pub mod proxy;
pub mod qr;
pub mod service;
pub mod share;
pub mod tunnel;
pub mod util;
pub mod vnet;
pub mod ws;

pub use config::{Config, Credentials, Protocol, ReconnectPolicy};
pub use ingress::{ForwardTarget, Ingress, IngressRule, OriginOptions, Service};
pub use metrics::{Metrics, MetricsSnapshot};
pub use share::{ShareApp, ShareConfig, ShareControl, ShareMode};
pub use tunnel::{Tunnel, TunnelBuilder, TunnelHandle};
pub use vnet::{NetStack, VirtAddr, VirtualSubnet};
pub use ws::LocalSpec;

/// Install the rustls crypto provider. Called automatically by
/// [`Tunnel::start`]; call it early if you build TLS yourself.
pub fn init_crypto() {
    net::init_crypto();
}
