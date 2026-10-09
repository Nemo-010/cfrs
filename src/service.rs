//! Prebuilt service runtimes: built-in origins are axum routers created once
//! at startup; forward services keep their rule + options.

use std::path::Path;
use std::sync::Arc;

use anyhow::{bail, Result};
use axum::Router;
use tower_http::services::{ServeDir, ServeFile};

use crate::gate::Gate;
use crate::ingress::{Ingress, OriginOptions, Service};
use crate::metrics::Metrics;
use crate::share::{ShareApp, ShareControl, ShareMode};

/// A service prepared for dispatch.
pub enum Built {
    /// HTTP / HTTPS / unix / unix+tls origin, proxied raw.
    Forward(Service, OriginOptions),
    /// Raw TCP origin.
    Tcp(Service, OriginOptions),
    HelloWorld,
    Status(u16),
    Static(Router),
    Metrics,
    Share(ShareApp),
    /// quickbridge proxy mode: gated forwarding to a local HTTP port.
    ShareProxy {
        target: String,
        gate: Gate,
        control: Arc<ShareControl>,
    },
}

pub struct ServiceRuntime {
    built: Vec<Built>,
    metrics: Metrics,
}

impl ServiceRuntime {
    /// Build every rule's runtime. Fails fast on a bad origin (missing
    /// directory, missing file) so the tunnel never starts half-configured.
    pub fn build(ingress: &Ingress, metrics: Metrics) -> Result<Self> {
        let mut built = Vec::with_capacity(ingress.rules.len());
        for rule in &ingress.rules {
            built.push(match &rule.service {
                Service::Http(_) | Service::Unix(_) | Service::UnixTls(_) => {
                    Built::Forward(rule.service.clone(), rule.origin.clone())
                }
                Service::Tcp(_) => Built::Tcp(rule.service.clone(), rule.origin.clone()),
                Service::HelloWorld => Built::HelloWorld,
                Service::Status(code) => Built::Status(*code),
                Service::Static { root, spa } => Built::Static(static_router(root, *spa)?),
                Service::Metrics => Built::Metrics,
                Service::Share(config) => match config.mode {
                    ShareMode::Proxy => Built::ShareProxy {
                        target: config
                            .target
                            .clone()
                            .unwrap_or_else(|| "127.0.0.1:80".to_string()),
                        gate: config.gate.clone(),
                        control: Arc::new(ShareControl::default()),
                    },
                    _ => Built::Share(ShareApp::new(config.clone())?),
                },
            });
        }
        Ok(Self { built, metrics })
    }

    pub fn get(&self, index: usize) -> Option<&Built> {
        self.built.get(index)
    }

    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    pub fn len(&self) -> usize {
        self.built.len()
    }

    pub fn is_empty(&self) -> bool {
        self.built.is_empty()
    }

    /// Session controls for every share rule, so a host can watch for
    /// `stop_after` and idle timeouts.
    pub fn share_controls(&self) -> Vec<Arc<ShareControl>> {
        self.built
            .iter()
            .filter_map(|built| match built {
                Built::Share(app) => Some(app.control()),
                Built::ShareProxy { control, .. } => Some(control.clone()),
                _ => None,
            })
            .collect()
    }
}

fn static_router(root: &Path, spa: bool) -> Result<Router> {
    if !root.is_dir() {
        bail!("static root is not a directory: {}", root.display());
    }
    let dir = ServeDir::new(root).append_index_html_on_directories(true);
    let router = if spa {
        let index = ServeFile::new(root.join("index.html"));
        Router::new().fallback_service(dir.not_found_service(index))
    } else {
        Router::new().fallback_service(dir)
    };
    Ok(router)
}
