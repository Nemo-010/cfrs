# cfrs third-party notices

`cfrs` itself is 0BSD (see `LICENSE`). It depends on, and in part reimplements
the wire behaviour of, the following work.

## cloudflare-quick-tunnel

- Source: https://crates.io/crates/cloudflare-quick-tunnel (version pinned `=0.3.1`)
- License: MIT OR Apache-2.0
- Used for: quick-tunnel provisioning, edge discovery, the QUIC dial, the
  Cap'n Proto registration RPC, and the per-request stream codec.

## cloudflared

- Source: https://github.com/cloudflare/cloudflared (studied at commit
  `bf4f5020be590fb9924c8982ac479a32f05de269`)
- License: Apache-2.0
- Used for: the Cap'n Proto schemas and the Cloudflare-internal CA roots that
  the edge's TLS certificate chains to, both vendored transitively by
  `cloudflare-quick-tunnel`.

## quickbridge

- Source: https://github.com/cfaulkingham/quickbridge
- License: MIT
- Used for: the session model that `cfrs share` reimplements — a PIN-gated
  upload/download/proxy session with a token path, transfer limits, stop-after
  and idle timeout. No code is copied; the behaviour is reimplemented on axum.

## Rust dependencies

`clap`, `tokio`, `quinn`, `rustls`, `httparse`, `reqwest`, `axum`, `tower`,
`tower-http`, `http-body-util`, `futures`, `tokio-util`, `serde`, `serde_json`,
`serde_yaml`, `base64`, `qrcode`, `webpki-roots`, `tracing`, `tracing-subscriber`,
`uuid`, `anyhow` and their transitive dependencies each carry their own
permissive licenses; `cargo metadata` lists them exhaustively.
