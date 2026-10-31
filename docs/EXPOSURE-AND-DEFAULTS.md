# Exposure and safe defaults

**Status:** proposal against `425e78c`. Not implemented.

`cfrs` publishes an origin through a CDN on purpose. That means three parties can see the
session and none of them can be made blind to it: **Cloudflare**, which terminates TLS and
keeps the authoritative record; **the local host**, which runs the process; and **any
network on the path**, which sees a TLS connection to a well-known zone. This document is
about what each of them sees, which parts are more than the operator intended, and which
defaults should change. Every claim is tied to a file and line so it can be checked.

It is not a document about making the session less visible. Reducing the flow's
observability would mean defeating a monitor rather than reducing an exposure, and the
tool's usefulness does not depend on it — see §5.

---

## 1. What each party sees

| Party | What it sees | Where |
| --- | --- | --- |
| **The edge** | source address, tunnel id, duration, volume, the inner bytes after TLS termination, and the tunnel's hostname. A named tunnel is attributable to an account; a quick tunnel has no tenant audit trail, which cuts both ways — nobody can attribute it, and nobody can audit it either | inherent |
| **The local host** | the process (`exe`, argv naming the origin and the mode), a local listener on `127.0.0.1` unless the operator asks otherwise (`src/ws.rs:184`), one long-lived outbound flow, and the byte counters | `src/main.rs`, `src/ws.rs:184` |
| **The network path** | TLS to `*.trycloudflare.com` or `*.argotunnel.com`; SNI names the zone and is not concealed; the inner protocol is visible only to a terminating proxy | inherent |
| **Anyone with the URL** | a quick tunnel is fully public. `share` gates it only when started with `--password` or in proxy mode (`src/main.rs:457-459`); `tunnel` and `serve` do not gate at all | `src/main.rs:457-459` |

Two of these are worth stating in the README because users consistently assume otherwise:

- **A quick tunnel is public.** `https://<random>.trycloudflare.com` is reachable by anyone
  who has the URL, and the URL is not something the tool keeps secret.
- **Publishing is not the same as protecting.** A directory served by `serve` is a
  directory on a public URL; the CDN does not add authorisation.

## 2. Defaults worth auditing

| Default | Current | Question |
| --- | --- | --- |
| local bind | `127.0.0.1` when unspecified (`src/ws.rs:184`) | good. Make it explicit in `--help` that a public bind must be asked for: the option is `-L/--local tcp://[bind:]port` (`src/main.rs:190-192`), and an empty bind already means loopback |
| `share` credentials | 6-digit PIN derived from a UUID (`src/gate.rs:34`) | see §3 |
| directory serving | `serve <dir>` | symlink escape, `..`, dotfiles, and whether the SPA fallback can return a file outside the root |
| `connect` | turns a local socket into a tunnel peer | which local addresses it will dial — loopback only, or anything reachable |
| config discovery | `cloudflared`-style YAML | a config file is an on-disk record naming the tunnel, readable by anyone the mode allows |

## 3. `share`'s PIN gate is the weakest component

Three defects, all cheap to fix and all currently unfixed:

1. **No attempt limiting.** `Gate::unlock` (`src/gate.rs:70-79`) compares the submitted PIN
   and returns a session cookie; nothing counts failures, and `src/proxy.rs:358-395` does
   not either. A 6-digit PIN is a 10⁶ space, so an unauthenticated party can walk it in
   roughly 28 hours at 10 attempts/second — and much faster with parallel connections. Add
   per-source rate limiting, a lockout with a delay, and a failure log.
2. **The cookie has no `Secure` attribute.** `src/gate.rs:76` sets
   `HttpOnly; SameSite=Lax; Max-Age=86400` but not `Secure`, so if the tunnel is reached
   over plain `http://` the cookie is also sent unencrypted. The edge leg is TLS; the
   browser-to-origin hop may not be. Add `Secure` when the request arrived over TLS.
3. **Non-constant-time comparison.** `password.trim() != self.pin` is a timing signal that
   is free to remove, and the kind of code that gets copied somewhere it matters.

The PIN itself (`Uuid::new_v4().as_u128() % 1_000_000`, `src/gate.rs:34`) is uniform enough
for six digits; if the same helper is ever used for a longer secret it should be `getrandom`
with rejection sampling.

## 4. What is fixed by the design

Stated so nobody spends a week on it: the edge terminates TLS and therefore sees the inner
bytes and keeps the record; SNI names the zone; the local host sees the process, its argv
and its listener. Those follow from what the tool is.

## 5. Out of scope, and why

- **Wire shaping aimed at a classifier** (fixed-size padding, splitting the ClientHello,
  imitating a browser's TLS profile). That targets a monitor rather than reducing an
  exposure, and it changes the wire in ways the edge's own tooling may treat as anomalous.
- **Hiding the process on its own host.** `cfrs` is a server the operator starts. A tool
  that conceals itself from the machine it runs on is a different product with a different
  threat model — and the operator is the person who needs to be able to see it.
- **Pooling quick-tunnel hostnames to spread volume.** That is free-tier arbitrage, not
  architecture. `README.md` already frames quick tunnels as temporary exposure.

## 6. Work items, in order

1. `share`: rate-limit and lock out PIN attempts, add `Secure` to the cookie, constant-time
   compare. *(security, user-facing)*
2. `serve`: audit path handling — symlink escape, `..`, dotfiles, SPA fallback — with a
   test for each. *(security)*
3. `connect`: state and enforce which local addresses may be dialled (loopback by default)
   and refuse the rest with a clear error. *(safety)*
4. `--help` and README: a short "what is public" section — quick tunnels are reachable by
   anyone with the URL, `share` gates only with `--password`, the edge sees the flow, the
   host sees the process. *(honesty)*
5. `docs/`: this file, kept current as the above land.
6. Preflight: refuse to `serve` a world-readable directory, or one containing `.env` or
   `.git`, without an explicit `--allow-exposed` flag. *(safe default)*

Items 1–3 are what a security release would carry; 4–6 are documentation and defaults.