# netbird-link — proposal summary

Two related ideas for an unprivileged NetBird client. Idea A came first; Idea B
came out of competitive research and is the stronger one. They share a runtime,
so this is a sequencing question, not an either/or.

Status: **design only. No code written.** Detailed version, including the full
competitive research, lives in the shared doc.

---

## TL;DR

Build **Idea B** (an SDK-backing agent exposing `dial` + `fetch`), and treat
**Idea A** (named local forwards) as one of its surfaces rather than as the
product. Do not build a C ABI or a WASM node yet.

The one-line reason: `fetch` is nearly free in every language via an HTTP
CONNECT proxy, and `dial` is universal via SOCKS5 — so an agent gives you
Go/JS/Python SDKs for roughly 200 lines each, with no FFI and no per-language
data plane.

---

## Idea A — rootless local forwarder

A small binary that embeds the client in userspace/netstack mode and forwards
local listeners into the overlay.

```
netbird-link --forward http://127.0.0.1:8080=https://grafana.internal
```

No TUN, no root, no `CAP_NET_ADMIN`; works on locked-down laptops and in
rootless containers. A proof of concept works today against a live network.

**Honest problem:** this is not novel, and two projects already are it —
`wireproxy` and `onetun` (userspace WireGuard, no root, static TCP/UDP forwards
plus SOCKS5 and an HTTP proxy, config-file driven). OpenZiti ships
`ziti tunnel proxy`; zrok ships nearly the same UX. It *is* a real gap among
WireGuard overlays specifically — Tailscale has no `-L` and Nebula has no
forwarding at all — but the claim has to be scoped that narrowly or it is false.

---

## Idea B — SDK agent (`dial` + `fetch`, polyglot)

A background userspace agent that owns the overlay connection, plus thin SDKs.

```python
nb   = netbird.connect()                      # attach to, or spawn, the agent
sock = nb.dial("db.internal", 5432)           # SOCKS5 under the hood
r    = nb.fetch("https://grafana.internal/")  # CONNECT proxy
```

**Why the agent model over FFI:** NetBird can embed a data-plane node in exactly
one language today — Go. OpenZiti gets ~8 languages from one `libziti` C core;
Tailscale gets ~5 from `libtailscale`. Paying that cost means a cgo
cross-compile matrix per OS/arch/language, prebuilt wheels and node-gyp
artifacts, and FFI lifetime management. The agent avoids all of it.

**`socks5h://` is the quiet win.** Remote DNS means the *agent* resolves the
name, so NetBird's in-process resolver serves every language for free — and it
sidesteps the upstream-DNS gap noted below.

Much of this already exists: 46 daemon RPCs with a complete grpc-gateway
projection (`client/proto/daemon.pb.gw.go`), kernel peer-credential auth
(`client/internal/ipcauth/`), and a go-socks5 proxy already running on
`127.0.0.1:1080` in netstack mode.

---

## How they relate

Idea A is a *surface* of Idea B. The agent needs listeners anyway; named
forwards are one kind, SOCKS5 and CONNECT are the other two. Building B first
and exposing A on top costs almost nothing extra. Building A first and
retrofitting B means writing the lifecycle, auth and control plane twice.

---

## Verified facts that shape the design

Read from the code, not assumed.

| Fact | Where | Consequence |
| --- | --- | --- |
| Userspace mode answers DNS in-process via packet hooks on the netstack device | `client/internal/dns/server.go:229` | No root, no `/etc/resolv.conf` edits. This is the core enabler. |
| **Upstream DNS uses netstack only when `GOOS=js`** | `client/internal/dns/upstream_general.go` | Split-DNS zones and overlay-only resolvers do **not** work unprivileged today. Fixable, but net-new. |
| **No system routes installed in netstack mode** (`useNoop`) | `client/internal/routemanager/manager.go:146` | Whether targets behind routing peers are reachable is **unverified**. Test this first — it can invalidate the use case. |
| `client/embed` takes a setup key or a **pre-obtained** JWT only | `client/embed/embed.go` | Interactive SSO is net-new work, not existing plumbing. |
| 46 daemon RPCs + HTTP/JSON gateway, behind `--enable-json-socket` | `client/proto/`, `client/cmd/service_*.go` | The control API mostly exists; it just defaults off. |
| WASM is force-relayed, 60 MB against a 62.9 MB CI gate, 17 fixed JS methods | `client/wasm`, `client/internal/peer/env.go` | Browser can never do direct P2P. WASM is not a path to a smaller binary. |
| Rootless image uses a **non-numeric** `USER`, and sets `NB_ENABLE_NETSTACK_LOCAL_FORWARDING=true` | `client/Dockerfile-rootless` | Not OpenShift-correct (arbitrary UID can't write state); the env var is documented as a security risk. Don't inherit either. |
| goreleaser has **no** implicit zip-on-Windows | `.goreleaser.yaml` | Set `format_overrides` explicitly. |

---

## Competitive read, short

| | Rootless | Static local forward | Names when rootless | SDK languages |
| --- | --- | --- | --- | --- |
| **Tailscale** | Yes (`--tun=userspace-networking`, `tsnet`) | **None** — no `-L`; SOCKS5/HTTP proxy or write Go | MagicDNS, but only inside its own dialer | ~5 via `libtailscale` |
| **Nebula** | Not in practice (needs TUN + `NET_ADMIN`) | **None**, at any privilege level | Effectively none | Go only, undocumented; **no JS at all** |
| **OpenZiti** | Yes (`ziti tunnel proxy`) | **Yes** — but binds `0.0.0.0` by default | **None** — DNS disabled in proxy mode; port map instead | **~8** via `libziti` |
| **NetBird** | Yes (netstack) | Proposed | Peer/local zones yes; upstream not yet | **Go only** |

`wireproxy` / `onetun` already occupy Idea A's exact space.
OpenZiti's browser stack is impressive but frozen since mid-2025; its BrowZer
mode overrides your CSP with `unsafe-eval` via an HTTP header.

---

## Open decisions

1. **Separate binary, or `netbird forward` / a mode of the existing client?**
   Tailscale made userspace a flag on the existing daemon and succeeded;
   OpenZiti split it into a second binary and that split is a known source of
   user confusion. Idea B weakens this objection — an SDK-backing agent is a
   genuinely different artifact from the user-facing CLI.
2. **Routing-peer reachability.** Run the experiment before anything else.
3. **Control API on a unix socket, not loopback TCP.** `ipcauth` gives real
   caller identity on a socket; a loopback listener has none, so any local
   process or web page could drive it.
4. **Background as a *user* service** (`systemd --user` + lingering, launchd
   `LaunchAgent`, Windows logon task) — never a root system service.
5. **SOCKS5 in v1?** Both research passes argued yes. A static port map does not
   scale past a handful of services.
6. **Does `client/embed` get a stability contract?** It becomes load-bearing,
   and it is absent from the high-risk list in `CONTRIBUTING.md`.
7. **Does each agent consume a peer slot?** Pricing question as much as
   technical; a thousand CI jobs is a thousand peers.

---

## Suggested order

1. **Spike:** routing-peer reachability + upstream DNS in netstack mode. Cheap,
   and either result reshapes everything below.
2. **Agent:** userspace node, SOCKS5 + CONNECT + named forwards, control API on
   a unix socket reusing the existing gateway and `ipcauth`. Fat binary is fine.
3. **Go SDK:** thin package over `client/embed`. Nearly free.
4. **Python + JS SDKs:** `dial` over SOCKS5, `fetch` over CONNECT, status over
   the control API. Ship the platform binary inside the npm/PyPI package the way
   esbuild and ripgrep do.
5. **C ABI — only if** the agent model proves insufficient. Decide deliberately.

**Not recommended:** a WASM node as the "small binary" path. Browser WASM is
relay-only forever (no raw UDP in the sandbox) and larger, not smaller. For
Node.js — which does have real UDP — a native addon over a C ABI beats WASM.
If binary size matters later, the lever is a module split, since `client/embed`
currently drags management, the IdP integrations, the pion ICE fork and gVisor.

---

## AGENTS.md notes

- PR title tag `[client]`; no tool-attribution trailers in commits or PR bodies.
- Keep PRs under ~400 lines, one purpose each.
- A Linear ticket is agreed before the first PR.
