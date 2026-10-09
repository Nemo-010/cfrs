# cfrs

Expose **anything** on the public Electrosphere through Cloudflare tunnels — an
anonymous quick tunnel (`https://<random>.trycloudflare.com`) or a named tunnel —
from a single Rust binary. No `cloudflared` subprocess, no Go, no account needed
for quick tunnels.

`cfrs` speaks the Cloudflare edge protocol directly (QUIC + Cap'n Proto RPC) and
adds a full service layer on top:

| Command | What it does |
| --- | --- |
| `cfrs tunnel` | Expose an HTTP(S) origin, a unix socket, a raw TCP port, `hello_world`, a fixed status, a directory, metrics, or a cloudflared-style YAML config. |
| `cfrs serve` | Serve a directory (optionally with SPA fallback) over a quick or named tunnel. |
| `cfrs share` | Upload / download / proxy session with a 6-digit PIN gate, an unguessable path, size caps, stop-after-transfer and idle timeout. |
| `cfrs ports` | List local listening TCP ports (Linux `/proc/net/tcp{,6}`). |
| `cfrs qr` | Render a URL as a terminal QR code. |
| `cfrs demo` | Self-contained proof: a built-in origin, a quick tunnel, then a fetch of the public URL. |

The whole thing is also a library; see [Library](#library).

## Install

```sh
cargo build --release
# ./target/release/cfrs
```

Requires Rust 1.86 or newer.

## Prove it works

`cfrs demo` starts a built-in origin, provisions a quick tunnel, registers with
the edge, and fetches the public URL to confirm the round trip:

```sh
cfrs demo --exit-on-verify
#   cfrs: public   https://<random>.trycloudflare.com
#   cfrs: edge     bog04
#   cfrs: PROOF    https://<random>.trycloudflare.com -> HTTP 200 (built-in hello world)
```

`--qr` prints a QR code for the URL, `--run-for <secs>` exits after a while, and
`--no-verify` skips the fetch.

## Expose a service

```sh
cfrs tunnel --url http://127.0.0.1:8080   # HTTP/HTTPS origin
cfrs tunnel --port 8080                   # shorthand for 127.0.0.1:8080
cfrs tunnel --unix /run/myapp.sock        # HTTP origin on a unix socket
cfrs tunnel --tcp 10.0.0.5:5432           # raw TCP origin
cfrs tunnel --hello-world                 # cloudflared's built-in origin
cfrs tunnel --config ./config.yml         # cloudflared-style ingress rules
```

Origins are parsed from cloudflared service strings:

```
http://host:port     https://host:port     unix:/path/to.sock
unix+tls:/path.sock  tcp://host:port       http_status:404
hello_world          metrics              static:/srv/www
spa:/srv/www
```

`static:` serves a directory; `spa:` adds an `index.html` fallback for
client-side routers. `metrics` renders Prometheus metrics for the tunnel.

`--http-host-header <H>` overrides the `Host` header sent upstream and
`--no-tls-verify` skips TLS verification for an HTTPS origin.

### Config file

`cfrs tunnel --config` reads a cloudflared-compatible YAML file:

```yaml
tunnel: <named-tunnel-token>          # optional; omit for a quick tunnel
credentials-file: /etc/cfrs/creds.json
ha-connections: 2
protocol: quic
ingress:
  - hostname: app.example.com
    path: /api
    service: http://127.0.0.1:8080
    originRequest:
      noTLSVerify: true
      connectTimeout: 5s
  - service: http_status:404
```

The last rule is normally a catch-all. `--token` and `--credentials-file` also
work on their own for named tunnels.

### Named tunnels

A named tunnel uses a Cloudflare account and a hostname you configure in the
dashboard. Pass the token or the credentials JSON file:

```sh
cfrs tunnel --token <token> --url http://127.0.0.1:8080
cfrs tunnel --credentials-file ~/.cloudflared/<id>.json --url http://127.0.0.1:8080
```

## Serve a directory

```sh
cfrs serve --dir ./public
cfrs serve --dir ./spa --spa          # fall back to index.html
cfrs serve --dir ./public --qr
```

## Share a file or folder

`cfrs share` is a quickbridge-style session. Uploads land in a directory,
downloads stream a single file, and proxy mode forwards a local HTTP port. The
public path is unguessable (`/s/<32-byte token>/`) and an optional 6-digit PIN
adds a session cookie; the PIN is shown only on the host.

```sh
# receive files into ~/Downloads/cfrs, PIN protected
cfrs share --mode upload --password

# share one file for download
cfrs share --mode download --file ./report.pdf

# expose a local HTTP port, PIN protected (always)
cfrs share --mode proxy --port 3000

cfrs share --mode upload --dir /tmp/inbox --stop-after --idle-secs 600
```

Uploads are capped (512 MiB per file, 32 files by default), filenames are
sanitized and made unique, and `--stop-after` ends the session after the first
successful transfer. `--idle-secs` ends it after inactivity.

## Sandboxes and unusual hosts

`cfrs` is built for hosts where the usual tunnel recipe does not fit:

- **Unix-socket origins.** Some sandboxes refuse `bind(2)` on `AF_INET` while
  allowing `AF_UNIX`; `--unix /path/to.sock` dials the socket instead.
- **QUIC over UDP/7844.** Where outbound TCP/7844 is blocked, the UDP path still
  works, and the edge is discovered by DNS SRV + DNS-over-TLS rather than a
  hard-coded address.
- **No `cloudflared`.** The protocol is implemented in-process, so the host needs
  no Go binary and no extra privileges.

## How it works

1. `POST https://api.trycloudflare.com/tunnel` returns a tunnel id, the public
   hostname, an account tag and a 32-byte secret.
2. A QUIC connection is opened to the edge with ALPN `argotunnel` and SNI
   `quic.cftunnel.com`.
3. The first bidirectional stream carries a Cap'n Proto RPC
   (`RegistrationServer.registerConnection`) that binds the tunnel to the edge.
   Additional connections with distinct `conn_index` values give HA.
4. Every stream the edge opens afterwards is one inbound request:
   `[signature][version][ConnectRequest]`, then bytes. `cfrs` forwards it to the
   origin and streams the response back. Reconnects use exponential backoff and
   re-register with `replace_existing`.

See [`PROTOCOL.md`](./PROTOCOL.md) for the wire format and the sandbox
measurements.

> The public URL is bound to the running process. It stops resolving the moment
> `cfrs` exits — a later visit returns Cloudflare **Error 1033** — and every run
> provisions a fresh random `*.trycloudflare.com` hostname. A quick tunnel is a
> courtesy service with no uptime guarantee and no confidentiality between the
> edge and the origin; do not use it for production or private data.

## Library

```rust
use cfrs::{Service, Tunnel};

# async fn run() -> anyhow::Result<()> {
let handle = Tunnel::quick()
    .service(Service::parse("http://127.0.0.1:8080")?)
    .ha_connections(2)
    .build()?
    .start()
    .await?;

println!("{:?}", handle.url());
handle.verify(None).await?;      // fetch the public URL
handle.shutdown().await;
# Ok(())
# }
```

Build an `Ingress` of ordered rules for multi-service tunnels, or pass a
`Config` directly. `TunnelHandle` exposes the public URL, edge locations,
metrics and the share session controls.

## License

0BSD. See [`LICENSE`](./LICENSE). Third-party components are listed in
[`THIRD_PARTY_NOTICES.md`](./THIRD_PARTY_NOTICES.md).

---

A Neucom Info release. Neucom Incorporated, Port Edwards — *to provide the
software that shapes the world of tomorrow*.
