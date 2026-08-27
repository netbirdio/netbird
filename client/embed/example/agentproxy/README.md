# agentproxy — a rootless local gateway into a NetBird Agent Network

`agentproxy` is a small proof-of-concept that turns any machine into a local
HTTP gateway into a [NetBird Agent Network](../../../../agent-network). It:

1. embeds the NetBird client in **userspace / netstack** mode — no TUN device,
   no `CAP_NET_ADMIN`, **no root**;
2. connects to NetBird the way a regular client does — **interactive SSO** by
   default, or a **setup key** from the environment when one is supplied;
3. runs a plain HTTP listener on `127.0.0.1:8080` and **reverse-proxies every
   request over the encrypted NetBird tunnel** to an upstream Agent Network
   endpoint (e.g. `https://mirror.netbird.ai`).

Because it only binds a loopback socket and never touches the kernel network
stack, it runs on locked-down laptops and in **rootless containers**
(OpenShift, Podman, distroless) where the standard agent cannot.

Point an AI agent (Claude Code, Codex, …) at `http://localhost:8080` and its
traffic flows through the identity-aware Agent Network proxy — with no API keys
handed to the agent.

## Build

```bash
go build -o agentproxy ./client/embed/example/agentproxy
```

## Run

Interactive SSO login (opens a browser, or prints the URL + device code when
there is no desktop session):

```bash
./agentproxy -upstream https://mirror.netbird.ai
```

Non-interactive, with a setup key (ideal for containers/CI):

```bash
NB_SETUP_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx \
  ./agentproxy -upstream https://mirror.netbird.ai
```

Then use it:

```bash
export ANTHROPIC_BASE_URL=http://localhost:8080
# ... run your agent ...
```

## Configuration

Flags take precedence over environment variables.

| Flag | Env var | Default | Description |
| --- | --- | --- | --- |
| `-upstream` | `NB_AGENT_UPSTREAM` | _required_ | Upstream agent network URL |
| `-listen` | `NB_LISTEN_ADDR` | `127.0.0.1:8080` | Local listen address |
| `-management-url` | `NB_MANAGEMENT_URL` | `https://api.netbird.io:443` | Management server URL |
| `-device-name` | `NB_DEVICE_NAME` | `agent-proxy` | Peer name in the network |
| `-no-browser` | — | `false` | Don't try to open the SSO URL |
| — | `NB_SETUP_KEY` | _unset_ | Setup key; when set, SSO is skipped |
| — | `NB_CONFIG_PATH` | in-memory | Persist client config to this path |
| — | `NB_STATE_PATH` | _unset_ | Persist client state to this path |
| — | `NB_HINT` | _unset_ | IdP login hint (email) for the SSO screen |
| — | `NB_LOG_LEVEL` | `warn` | Embedded client log level |

By default nothing is written to disk (config and keys live only in memory);
set `NB_CONFIG_PATH` / `NB_STATE_PATH` to persist the peer identity across
restarts.

## How it works

```
AI agent ──HTTP──▶ 127.0.0.1:8080 (agentproxy)
                        │  httputil.ReverseProxy
                        │  Transport.DialContext = embedded client dialer
                        ▼
                 NetBird overlay (userspace WireGuard, netstack)
                        │  magic DNS resolves e.g. mirror.netbird.ai
                        ▼
              Agent Network reverse proxy (identity, policy, limits)
                        ▼
                 LLM API / AI gateway
```

The reverse proxy's `Transport.DialContext` is the embedded client's dialer, so
every upstream connection is established inside the WireGuard tunnel, and the
outgoing `Host` header is set to the upstream host so TLS SNI and the Agent
Network's identity-aware routing see the real endpoint.

### DNS resolution happens *inside* the process — no root, no `/etc/resolv.conf`

This is the important part for locked-down hosts. The proxy **never touches the
system resolver**. In userspace/netstack mode NetBird runs its DNS server "via
memory": it registers UDP/TCP packet hooks on the in-process netstack device
(`ServiceViaMemory`) for a reserved tunnel DNS IP. When the netstack dialer
resolves the upstream hostname it sends the DNS query *over the tunnel* to that
IP, where the hook answers it from the NetBird network map:

```
client.Dial("mirror.netbird.ai:443")
  └─ netstack Net.LookupContextHost  (in-process)
       └─ DNS query to the reserved tunnel DNS IP
            └─ ServiceViaMemory packet hook answers from the network map
                 └─ overlay IP → netstack dials it through WireGuard
```

Because the resolver lives in the netstack and is fed by the network map, the
process resolves NetBird names on its own — it does **not** rely on the host's
`/etc/resolv.conf`, systemd-resolved, or any change that would need root. (The
`netbird` daemon's `noop host manager` in netstack mode only means it skips
editing the OS resolver; the in-memory DNS server still answers in-process.)
This is the same mechanism the WASM client and the Agent Network reverse proxy
rely on.

For the upstream name to resolve, it must be known to your NetBird DNS (a peer
FQDN, a custom DNS record/zone, or a matching nameserver group) and a policy
must grant this peer access to the agent network.

## Logs and troubleshooting

The process is deliberately noisy about what it is doing:

- On connect it logs the assigned overlay IP/FQDN, management/signal state, and
  the peer count.
- A **preflight** step resolves and dials the upstream over the tunnel once at
  startup and logs the result, so a DNS/policy problem shows up immediately
  rather than on the first request.
- Each proxied request logs a `-> METHOD /path` / `<- METHOD /path STATUS (dur)`
  pair, and each tunnel dial logs the resolved local/remote tunnel addresses.

Example startup:

```
connected to NetBird network: ip=100.72.0.5 fqdn=agent-proxy.netbird.cloud management=true signal=true peers=3
preflight: resolving and dialing mirror.netbird.ai:443 over the tunnel ...
preflight: reached mirror.netbird.ai:443 (tunnel 100.72.0.5:52344 -> 100.72.0.9:443)
listening on http://127.0.0.1:8080 -> https://mirror.netbird.ai (over NetBird)
```

Set `NB_LOG_LEVEL=debug` (or `trace`) to surface the embedded client's own
management/signal/relay handshakes, DNS setup, and per-peer connection detail.
If the preflight cannot reach the endpoint, the two most common causes are that
the upstream name is not resolvable in your NetBird DNS, or that no policy grants
this peer access to the agent network.

> **Proof of concept.** Intended to demonstrate the embedded-client + local
> forward-proxy pattern for rootless environments. Not hardened for production.
