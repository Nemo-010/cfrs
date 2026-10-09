# cfrs

Expose a local HTTP server on the public Electrosphere through an **anonymous
Cloudflare quick tunnel** — `https://<random>.trycloudflare.com` — from a single
Rust binary. No Cloudflare account, no API token, no `cloudflared` subprocess.

`cfrs` is built for hosts where the usual tunnel recipe does not fit:

- **The local origin may be a unix socket.** Some sandboxes refuse `bind(2)` on
  `AF_INET` while allowing `AF_UNIX`. `cfrs --unix /path/to.sock` dials the
  socket instead of a TCP port.
- **The transport is QUIC over UDP/7844.** Where outbound TCP/7844 is blocked,
  the UDP path still works, and `cfrs` speaks the edge protocol directly.

The Cloudflare quick-tunnel protocol is implemented by the
[`cloudflare-quick-tunnel`](https://crates.io/crates/cloudflare-quick-tunnel)
crate (QUIC + Cap'n Proto RPC, no Go binary). `cfrs` supplies the unix-socket
origin proxy, provisioning, supervision and end-to-end verification. See
[`PROTOCOL.md`](./PROTOCOL.md) for the wire format and the sandbox measurements.

## Install

```sh
cargo build --release
# ./target/release/cfrs
```

Requires Rust 1.86 or newer.

## Use

Prove exposure with no external server at all — `cfrs` starts a tiny HTTP origin
on a unix socket, exposes it, and fetches the public URL to confirm:

```sh
cfrs --demo --exit-on-verify
#   cfrs: origin  unix:/tmp/cfrs-demo.sock
#   cfrs: public  https://<random>.trycloudflare.com
#   cfrs: edge    bog04
#   cfrs: PROOF   https://<random>.trycloudflare.com -> HTTP 200 (97 bytes, token matched)
```

Expose a server you already run on a unix socket:

```sh
cfrs --unix /run/myapp.sock
```

Expose a server on a TCP port (ordinary hosts):

```sh
cfrs --port 8080
```

Flags: `--no-verify` skips the proof fetch, `--run-for <secs>` exits after a
while, `--exit-on-verify` exits as soon as the public URL answers. QUIC is
UDP-only; if `--no-verify` is used and the host cannot reach `api.trycloudflare.com`
over 443, provisioning fails before any tunnel is created.

## How it works

1. `POST https://api.trycloudflare.com/tunnel` returns a tunnel id, the public
   hostname, an account tag and a 32-byte secret.
2. A QUIC connection is opened to `region{1,2}.v2.argotunnel.com:7844` with ALPN
   `argotunnel` and SNI `quic.cftunnel.com`.
3. The first bidirectional stream carries a Cap'n Proto RPC
   (`RegistrationServer.registerConnection`) that binds the tunnel to the edge.
4. Every stream the edge opens afterwards is one inbound request:
   `[signature][version][ConnectRequest]`, then bytes. `cfrs` forwards it to the
   origin and streams the response back.

A quick tunnel is a courtesy service with no uptime guarantee and no
confidentiality between the edge and the origin; do not use it for production or
private data.

## License

0BSD. See [`LICENSE`](./LICENSE). Third-party components are listed in
[`THIRD_PARTY_NOTICES.md`](./THIRD_PARTY_NOTICES.md).

---

A Neucom Info release. Neucom Incorporated, Port Edwards — *to provide the
software that shapes the world of tomorrow*.
