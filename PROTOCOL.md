# The Cloudflare quick-tunnel protocol, and what works in a sealed sandbox

This is the deep dive behind `cfrs`. The reference implementation is
`cloudflare/cloudflared`, studied at commit
`bf4f5020be590fb9924c8982ac479a32f05de269` (2026-10-08). File references below
are to that tree; the behaviour is mirrored by the `cloudflare-quick-tunnel`
crate that `cfrs` uses.

## 1. Control plane — provisioning

`cloudflared tunnel --url ...` with no account runs `RunQuickTunnel`
(`cmd/cloudflared/tunnel/quick_tunnel.go`). It issues exactly one request:

```
POST https://api.trycloudflare.com/tunnel
Content-Type: application/json
User-Agent: cloudflared/<version>
```

The body is empty for a public quick tunnel. For a **protected** (email
allow-list) quick tunnel the body is `{"auth_mode":"otp"}` and the CLI is given
`--allowed-mail` (`buildQuickTunnelRequestBody`). A successful response is:

```json
{"success":true,"result":{
  "id":"<uuid>","name":"qt-...","hostname":"<random>.trycloudflare.com",
  "account_tag":"<hex>","secret":"<base64 32 bytes>"},"errors":[]}
```

`id`, `account_tag` and `secret` are the `TunnelAuth` credentials the edge wants
on registration. The endpoint is overridable with `--quick-service`; the
default is hard-coded at `cmd/cloudflared/tunnel/cmd.go:872`. The provisioning
call is plain HTTPS on 443 — this is the only part that is trivially reachable
from a normal network.

### The email allow-list

The newer protected mode (`quicktunnelauth/`) does not put the mailbox list in
the provisioning request. `--allowed-mail` builds a local
`QuickTunnelAuthRecipientPolicy`; the local cloudflared then runs an OTP gate in
front of the tunnel: an unauthenticated browser is redirected to
`https://login.trycloudflare.com`, which returns a signed ES256 JWT
(`quick_tunnel_auth` assertion) bound to the quick-tunnel hostname and a
one-time state. The validator checks issuer `https://login.trycloudflare.com`,
audience `cloudflared-quick-tunnel`, a 2-minute TTL, the callback hostname and
the recipient policy (`quicktunnelauth/assertion.go`, `handler.go`). In other
words the allow-list is enforced at the **origin-side cloudflared**, not by the
edge, and it is unavailable to a client that only speaks the tunnel protocol.

## 2. Data plane — the edge connection

Edge addresses come from the SRV record
`_v2-origintunneld._tcp.argotunnel.com`, which yields
`region1.v2.argotunnel.com` / `region2.v2.argotunnel.com` on port **7844**
(`edgediscovery/allregions`). Two transports are supported
(`connection/protocol.go`):

| protocol | socket | TLS SNI | ALPN |
| --- | --- | --- | --- |
| `quic` | UDP 7844 | `quic.cftunnel.com` | `argotunnel` |
| `http2` | TCP 7844 | `h2.cftunnel.com` | `h2` |

`auto` tries QUIC first and falls back to HTTP/2. `cloudflared`'s own prechecks
name the reachability requirements literally: `Allow outbound QUIC traffic on
port 7844 or use HTTP2.` and `Allow outbound TCP on port 7844.`
(`prechecks/probes.go:31-32`).

The edge's certificate chains to Cloudflare-internal CAs that are not in the
public trust store; `cloudflared` ships them in `tlsconfig/cloudflare_ca.go`,
and any reimplementation must add them or the handshake fails `UnknownIssuer`.

On the QUIC connection the **first bidirectional stream is the control plane**.
It is not prefixed with the per-request signature; it carries Cap'n Proto RPC
directly, and the client calls
`RegistrationServer.registerConnection(auth, tunnelId, connIndex, options)`
(`tunnelrpc/registration_client.go`, served from
`connection/quic_connection.go::Serve`). Every stream after that is an inbound
request from the edge.

## 3. Per-request stream framing

An inbound stream begins with a 6-byte signature, a 2-byte version and a Cap'n
Proto `ConnectRequest` carrying the destination URL, the connection type
(`Http` / `Websocket` / `Tcp`) and metadata (`HttpMethod`, `HttpHost`, and one
`HttpHeader:<Name>` entry per header). The client replies with the analogous
`ConnectResponse` (status + headers) and then the stream is a byte pipe. The
schemas are `schemas/quic_metadata_protocol.capnp` and `schemas/tunnelrpc.capnp`.

## 4. Measurements in a sealed sandbox

Measured on the host where `cfrs` was developed, using the route setup from
`sandhome` (no privilege, no pty, no `/etc/passwd`, `bind=unix`):

| probe | result |
| --- | --- |
| outbound TCP to `github.com:{22,53,80,7844,8080,8443}` | `connect: Permission denied` |
| outbound TCP to any host `:443` | works |
| outbound UDP to edge `:7844` | works — `cloudflared` precheck: `QUIC connection successful` |
| `bind(2)` `AF_INET` `127.0.0.1:0`, `0.0.0.0:0`, `[::1]:0` | `EACCES` |
| `bind(2)` `AF_UNIX` | works |
| `POST https://api.trycloudflare.com/tunnel` | HTTP 200, real hostname + credentials |
| TLS to the tunnel anycast on `:443` (SNI `h2.cftunnel.com`) | legacy 2020 certificate, not the tunnel service |

The consequences are direct:

- The HTTP/2 transport is dead here (TCP 7844 blocked), and the tunnel service
  is not served on 443. **QUIC over UDP 7844 is the only viable transport.**
- No TCP listener can be created, so the origin must be `AF_UNIX`. `cloudflared`
  itself can only expose a unix origin through a config-file ingress
  (`service: unix:/path`); `--unix-socket` is mutually exclusive with the
  `--url` that triggers quick-tunnel mode, and quick-tunnel mode is only
  triggered by `--url` or `--hello-world`. `cfrs` sidesteps that by running the
  protocol itself.
- A quick tunnel also needs a locally served origin; the built-in
  `--hello-world` origin binds TCP and therefore cannot start here.

## 5. Reproducing the proof

`cfrs --demo --exit-on-verify` does all of it: it binds an `AF_UNIX` HTTP origin,
provisions a quick tunnel against `api.trycloudflare.com` (443), registers over
QUIC to the edge (UDP 7844), then fetches the public `https://<random>.trycloudflare.com`
URL and checks that the response contains the origin's random token. A run
prints the public URL, the edge POP, and `PROOF ... HTTP 200`.

For comparison, the reference binary reproduces the transport finding but not
the unix origin:

```sh
# origin
python3 -m http.server 8080
# transport test (TCP 7844 blocked here, so QUIC is selected)
cloudflared tunnel --url http://127.0.0.1:8080
# with a unix origin, triggered through a config file:
printf 'ingress:\n  - service: unix:/tmp/origin.sock\n' > cf.yml
cloudflared tunnel --config cf.yml --url http://placeholder.invalid --protocol quic
```
