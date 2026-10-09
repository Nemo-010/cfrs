//! Tunnel metrics with a Prometheus text renderer.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Clone, Default)]
pub struct Metrics {
    inner: Arc<Inner>,
}

#[derive(Default)]
struct Inner {
    streams_total: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    active_streams: AtomicU64,
    reconnects: AtomicU64,
    connections: AtomicU64,
    errors: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MetricsSnapshot {
    pub streams_total: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub active_streams: u64,
    pub reconnects: u64,
    pub connections: u64,
    pub errors: u64,
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn stream_started(&self) {
        self.inner.streams_total.fetch_add(1, Ordering::Relaxed);
        self.inner.active_streams.fetch_add(1, Ordering::Relaxed);
    }

    pub fn stream_finished(&self) {
        self.inner.active_streams.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn add_in(&self, bytes: u64) {
        self.inner.bytes_in.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn add_out(&self, bytes: u64) {
        self.inner.bytes_out.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn reconnect(&self) {
        self.inner.reconnects.fetch_add(1, Ordering::Relaxed);
    }

    pub fn connection_opened(&self) {
        self.inner.connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn error(&self) {
        self.inner.errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            streams_total: self.inner.streams_total.load(Ordering::Relaxed),
            bytes_in: self.inner.bytes_in.load(Ordering::Relaxed),
            bytes_out: self.inner.bytes_out.load(Ordering::Relaxed),
            active_streams: self.inner.active_streams.load(Ordering::Relaxed),
            reconnects: self.inner.reconnects.load(Ordering::Relaxed),
            connections: self.inner.connections.load(Ordering::Relaxed),
            errors: self.inner.errors.load(Ordering::Relaxed),
        }
    }

    /// Prometheus exposition format.
    pub fn prometheus(&self) -> String {
        let m = self.snapshot();
        format!(
            "# HELP cfrs_streams_total Inbound streams handled.\n\
             # TYPE cfrs_streams_total counter\n\
             cfrs_streams_total {}\n\
             # HELP cfrs_active_streams Streams currently being proxied.\n\
             # TYPE cfrs_active_streams gauge\n\
             cfrs_active_streams {}\n\
             # HELP cfrs_bytes_in_total Bytes received from the edge.\n\
             # TYPE cfrs_bytes_in_total counter\n\
             cfrs_bytes_in_total {}\n\
             # HELP cfrs_bytes_out_total Bytes sent to the edge.\n\
             # TYPE cfrs_bytes_out_total counter\n\
             cfrs_bytes_out_total {}\n\
             # HELP cfrs_reconnects_total Edge reconnections.\n\
             # TYPE cfrs_reconnects_total counter\n\
             cfrs_reconnects_total {}\n\
             # HELP cfrs_connections_total Edge connections registered.\n\
             # TYPE cfrs_connections_total counter\n\
             cfrs_connections_total {}\n\
             # HELP cfrs_errors_total Stream or connection errors.\n\
             # TYPE cfrs_errors_total counter\n\
             cfrs_errors_total {}\n",
            m.streams_total,
            m.active_streams,
            m.bytes_in,
            m.bytes_out,
            m.reconnects,
            m.connections,
            m.errors
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_and_renders() {
        let metrics = Metrics::new();
        metrics.stream_started();
        metrics.add_in(10);
        metrics.add_out(20);
        metrics.stream_finished();
        let snap = metrics.snapshot();
        assert_eq!(snap.streams_total, 1);
        assert_eq!(snap.active_streams, 0);
        assert_eq!(snap.bytes_in, 10);
        assert_eq!(snap.bytes_out, 20);
        let text = metrics.prometheus();
        assert!(text.contains("cfrs_streams_total 1"));
        assert!(text.contains("cfrs_bytes_out_total 20"));
    }
}
