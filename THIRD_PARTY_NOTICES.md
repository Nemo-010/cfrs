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

## Design references

Behaviour was studied (not copied) from these projects:

- [erebe/wstunnel](https://github.com/erebe/wstunnel) and
  [vi/websocat](https://github.com/vi/websocat) (MIT): carrying raw TCP/unix
  streams over WebSockets, which `--forward` / `cfrs connect` reimplement.
- [LauJangit/cloudflare-quick-tunnel](https://github.com/LauJangit/cloudflare-quick-tunnel)
  and [TejasPersonal/flared-rust](https://github.com/TejasPersonal/flared-rust):
  notes on the HTTP/2 edge transport (client SNI `h2.cftunnel.com`, empty ALPN,
  the local process as the H2 server) and on treating origin readiness as a
  separate fact from "the URL is known".
- [tutoihoc/sillytavern-modelscope](https://github.com/tutoihoc/sillytavern-modelscope):
  the measured quick-tunnel streaming behaviour (POST `text/event-stream`
  streams, GET does not) and stripping `Accept-Encoding` to avoid edge
  buffering.
- [aminahwulanjohan-sudo/cf-tunnel-egress-proxy](https://github.com/aminahwulanjohan-sudo/cf-tunnel-egress-proxy):
  the `socat` + `HTTP CONNECT` egress-proxy recipe for reaching TCP 7844. It is
  documented in `PROTOCOL.md` along with the measurement showing why it does not
  apply to a port-filtered sandbox.
- [tailscale/tailcat](https://github.com/tailscale/tailcat) and
  [JustinGrote/PoshAnywhere](https://github.com/JustinGrote/PoshAnywhere):
  out-of-band connection metadata and "phone home" transports. Not implemented;
  listed so the lineage is clear.

## Rust dependencies

`clap`, `tokio`, `quinn`, `rustls`, `httparse`, `reqwest`, `axum`, `tower`,
`tower-http`, `http-body-util`, `futures`, `tokio-util`, `serde`, `serde_json`,
`serde_yaml`, `base64`, `qrcode`, `webpki-roots`, `tokio-tungstenite`, `sha1`,
`tracing`, `tracing-subscriber`, `uuid`, `anyhow` and their transitive
dependencies each carry their own permissive licenses; `cargo metadata` lists
them exhaustively.
