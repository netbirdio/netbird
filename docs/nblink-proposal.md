# nblink proposal

`nblink` is a single unprivileged binary that gives a machine a local door into a
NetBird network. It embeds the client in netstack mode, authenticates the way a
regular client does, and opens local listeners that forward into the overlay.

No TUN, no root, no `CAP_NET_ADMIN`. It runs on locked-down laptops and in
rootless containers such as OpenShift and Podman, where the normal agent cannot.

Two delivery shapes, same binary:

1. Download and run. One static binary, no installer, no service to register.
2. A rootless container image configured entirely through environment variables.

Status: design only, no code written. A working proof of concept exists and was
confirmed against a live network.

## Why

Among WireGuard overlays this is a real gap. Tailscale has no `-L` and no
`forward` subcommand; the only options are a dynamic proxy, a stdio pipe, or
writing Go against `tsnet`. Nebula has no forwarding at any privilege level, and
its pull request for it has been open since 2024.

A dynamic proxy does not substitute for a forward, because `psql`, most database
drivers, many gRPC clients, `kubectl` and git-over-ssh ignore `ALL_PROXY`. That
is why Tailscale users end up in `proxychains`.

Scope the claim honestly. OpenZiti's `ziti tunnel proxy` and zrok already do
this, and `wireproxy` and `onetun` are userspace WireGuard forwarders that
occupy nearly the same space. The gap is specific to NetBird and its peers, not
to the industry.

## What it does

A forward is one self-describing token, repeatable:

```
nblink --forward 'tcp://127.0.0.1:5432=db.internal:5432' \
       --forward 'http://127.0.0.1:8080=https://grafana.internal'
```

The scheme on the left is the listener type. The right side is the overlay
target, resolved inside the tunnel. Omitting the bind host defaults it to
`127.0.0.1`. The grammar takes `tcp://`, `http://`, `udp://` and `socks5://`
without change, so later protocols need no new flag.

Names on the right resolve through NetBird's in-process resolver, so
`/etc/resolv.conf` is never touched and no root is needed for DNS.

## Interface

Flags are the only definition. NetBird already derives environment variables
from flag names (`FlagNameToEnvVar(f.Name, "NB_")`), so every flag gets an
`NB_`-prefixed variable for free and the container surface stays in lockstep
with the CLI instead of drifting from it.

| Flag | Environment | Notes |
| --- | --- | --- |
| `--forward` | `NB_FORWARD` | Repeatable. As a `StringSlice`, the env form is comma separated. |
| `--socks5` | `NB_SOCKS5` | Dynamic egress on one port. Off unless set. |
| `--setup-key` | `NB_SETUP_KEY` | Accepts a `file:` prefix for container secrets. |
| `--management-url` | `NB_MANAGEMENT_URL` | Defaults to the NetBird cloud endpoint. |
| `--hostname` | `NB_HOSTNAME` | Peer name in the network. |
| `--state-dir` | `NB_STATE_DIR` | Persists identity across restarts. In memory when unset. |
| `--log-level` | `NB_LOG_LEVEL` | Defaults to `info`. |
| `--allow-public-bind` | `NB_ALLOW_PUBLIC_BIND` | Required before any non-loopback bind. |
| `--check` | `NB_CHECK` | Validate config, print the effective set, exit non-zero on error. |

Laptop, interactive login:

```
nblink --forward 'tcp://5432=db.internal:5432'
```

Container, everything through the environment:

```
docker run --rm -p 5432:5432 \
  -e NB_SETUP_KEY=file:/run/secrets/nb_setup_key \
  -e NB_FORWARD='tcp://0.0.0.0:5432=db.internal:5432' \
  -e NB_ALLOW_PUBLIC_BIND=true \
  netbirdio/nblink
```

Authentication is a setup key when one is present, and an interactive browser
flow otherwise, printing the URL so it still works over SSH. This is net-new
code: `client/embed` accepts a setup key or a pre-obtained JWT only, and the
device-code and PKCE flows live in the CLI today.

## Security defaults

- Bind `127.0.0.1` unless `--allow-public-bind` is passed. A forwarder on
  `0.0.0.0` lets anything on the pod or office network into the overlay.
  `ziti tunnel proxy` defaults to `0.0.0.0` and is the counter-example.
- Containers publish ports explicitly, so binding `0.0.0.0` inside the container
  is normal. Keep it opt-in anyway so the default is safe in both shapes.
- SOCKS5 requires a generated credential. `tailscaled` constructs its SOCKS5
  server with no credentials, which is why `TS_SOCKS5_SERVER=:1055` publishes an
  unauthenticated proxy into the tailnet.
- `BlockInbound` and `BlockLANAccess` stay on, so the peer is never a stepping
  stone into the host's network.
- Do not inherit `NB_ENABLE_NETSTACK_LOCAL_FORWARDING=true` from
  `client/Dockerfile-rootless`. `client/firewall/uspfilter/filter.go` documents
  it as a risk, because localhost-only sockets become reachable.
- Fail closed on a bad forward spec rather than starting a partial set.
- Never log setup keys or tokens.

## What v1 is not

No exit node, no subnet router, no system DNS takeover, no privileged ports, no
host-stack ICMP. netstack carries TCP, UDP and ping only. Enumerate these in the
README and reject them in code with a specific message, because an undocumented
limit is what generates support load.

## Packaging

**Binary.** A `netbird-link` build entry in the existing `.goreleaser.yaml`
alongside `netbird-proxy`, with `CGO_ENABLED=0`, built for Linux, macOS and
Windows on amd64, arm64 and arm. Archives need `format_overrides` set
explicitly, because goreleaser hardcodes tar.gz and NetBird's current Windows
`.zip` comes from a separate signing pipeline that `nblink` would not inherit.

**Container.** A new rootless image modeled on `proxy/Dockerfile`, with three
corrections:

- A numeric `USER`, plus `chgrp -R 0` and `chmod -R g=u` on the state directory.
  OpenShift assigns an arbitrary UID whose only supplemental group is 0, so the
  current `client/Dockerfile-rootless` with its named `USER netbird:netbird`
  leaves state unwritable.
- Base on `gcr.io/distroless/static-debian13`. The debian12 tag was deprecated
  in August 2026.
- Never depend on a passwd lookup, so no `os/user.Current()` and no `~`
  expansion for the state path. OpenShift's guidance wants no `/etc/passwd`
  entry so CRI-O can inject a random UID.

Add a CI job that runs the image under `--user <random-high-uid>:0`, because the
OpenShift breakage above is invisible until someone tries it.

## Risk to settle first

`client/internal/routemanager/manager.go:146` sets
`useNoop := netstack.IsEnabled() || config.DisableClientRoutes`, so no system
routes are installed in netstack mode. Whether the netstack's own route table
carries advertised prefixes is unverified.

Most interesting targets, a database in a VPC or an internal Grafana, sit behind
a routing peer rather than on the overlay. If netstack reaches only peer IPs,
v1's use cases shrink sharply. Run this experiment before writing anything else.

A second check worth doing at the same time: `client/internal/dns/upstream_general.go`
only routes upstream DNS through netstack when `GOOS=js`, so a nameserver that
exists only inside the overlay is not reachable from an unprivileged client
today. Peer and local-zone records are unaffected.

## Repo layout

```
client/link/
├── cmd/nblink/main.go    parse, build config, run
├── config.go             flags, env, validation
├── link.go               lifecycle and listener supervision
├── auth.go               setup key and interactive SSO
├── forward_tcp.go        v1
├── observe.go            startup lines, access log, status, preflight
└── README.md
```

`forward_http.go`, `forward_udp.go` and `forward_socks5.go` drop in later
without restructuring. The binary is `nblink`; the goreleaser id and image stay
`netbird-link` for consistency with `netbird-proxy`.

## Delivery

One purpose per PR, each useful on its own, tagged `[client]`.

| # | Scope | Size |
| --- | --- | --- |
| 1 | Core: config, auth, lifecycle, observability, TCP forward | ~350 lines |
| 2 | Packaging: container image, goreleaser build and archive entries | ~80 lines |
| 3 | HTTP forward, with Host and TLS overrides | small |
| 4 | SOCKS5 with a generated credential | medium |

Packaging lands second so the thing is downloadable early, which is the point of
the project.

## Open decisions

1. **Separate binary, or `netbird forward`?** Tailscale made userspace a flag on
   the existing daemon and succeeded. OpenZiti split it into a second binary and
   that split is a known source of user confusion. A subcommand inherits signing,
   notarization, packaging, docs and the SSO flow for free, and the decision is
   reversible in only one direction.
2. **TCP first or HTTP first?** This proposal puts TCP first, because the clients
   that cannot use a proxy are the reason the product exists. The earlier plan
   said HTTP.
3. **Is SOCKS5 v1 rather than PR 4?** A static port map does not scale past a
   handful of services, which is the standing complaint against OpenZiti's proxy
   mode.
4. **Does each `nblink` instance consume a peer slot?** A thousand CI jobs a day
   is a thousand peers. Pricing question as much as a technical one.
5. **Does `client/embed` get a stability contract?** It becomes load-bearing here
   and is absent from the high-risk list in `CONTRIBUTING.md`.

## Later parts

An SDK-backing agent exposing `dial` and `fetch` to Go, Python and JavaScript is
the larger opportunity, since NetBird can embed a data-plane node in Go alone
while comparable overlays project one C core into roughly eight languages. A
forwarder with SOCKS5 is most of the runtime that idea needs, so nothing here
blocks it. Tracked separately.
