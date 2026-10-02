# nblink

`nblink` forwards local ports into a NetBird network from an unprivileged
process. It runs the client in userspace mode, so there is no TUN device to
create and no elevated privileges to grant. That lets it run on managed
machines and in rootless containers where the normal agent cannot.

Overlay names on the upstream side are resolved inside the tunnel, so
`/etc/resolv.conf` is never touched.

## Install

Download the archive for your platform, extract it, and run the binary. There
is no installer and no service to register.

## Use

A forward is one self-describing argument, and the flag repeats:

```sh
nblink --forward 'http://8080=https://grafana.internal'
```

The scheme on the left selects the listener type. The right side is the
upstream reached over the network. Giving only a port binds loopback, so the
example above listens on `127.0.0.1:8080`.

Without a setup key, `nblink` opens a browser to log in and prints the URL so
it also works over SSH.

```sh
# several forwards from one session
nblink --forward 'http://8080=https://grafana.internal' \
       --forward 'http://9090=https://prometheus.internal'

# non-interactive
nblink --forward 'http://8080=https://grafana.internal' --setup-key "$NB_SETUP_KEY"

# check the configuration without touching the network
nblink --forward 'http://8080=https://grafana.internal' --check
```

Port `0` asks the operating system for a free port. The address actually bound
is printed at startup.

## Container

Every flag has a matching `NB_`-prefixed environment variable, which is how the
image is configured. `NB_FORWARD` takes a comma separated list.

```sh
docker run --rm -p 8080:8080 \
  --mount type=bind,src="$(pwd)/nb_setup_key",dst=/run/secrets/nb_setup_key,readonly \
  -e NB_SETUP_KEY=file:/run/secrets/nb_setup_key \
  -e NB_FORWARD='http://0.0.0.0:8080=https://grafana.internal' \
  -e NB_ALLOW_PUBLIC_BIND=true \
  netbirdio/nblink
```

The image needs no `--privileged`, no `--cap-add NET_ADMIN`, no
`--device /dev/net/tun` and no host networking.

Inside a container the listener usually binds `0.0.0.0`, because the container
boundary is what restricts access and the port is published explicitly. That
still requires `NB_ALLOW_PUBLIC_BIND`, so the safe default holds everywhere and
exposing a forward is always something the operator wrote down.

Set `NB_STATE_DIR` to a writable volume to keep the peer identity across
restarts. Without it, the peer is new on every start.

## Configuration

| Flag | Environment | Default | Purpose |
| --- | --- | --- | --- |
| `--forward` | `NB_FORWARD` | | Forward spec, repeatable. Comma separated in the environment. |
| `--setup-key` | `NB_SETUP_KEY` | | Non-interactive login. Accepts a `file:` prefix. |
| `--management-url` | `NB_MANAGEMENT_URL` | NetBird cloud | Management server. |
| `--hostname` | `NB_HOSTNAME` | host name | Peer name in the network. |
| `--state-dir` | `NB_STATE_DIR` | memory | Where identity and state persist. |
| `--log-level` | `NB_LOG_LEVEL` | `info` | Log level. |
| `--allow-public-bind` | `NB_ALLOW_PUBLIC_BIND` | `false` | Required before binding a non-loopback address. |
| `--no-browser` | `NB_NO_BROWSER` | `false` | Print the login URL instead of opening a browser. |
| `--check` | `NB_CHECK` | `false` | Validate, print the effective forwards, exit. |

A secret given as `file:/path` is read from that file, so a container can mount
it instead of exposing it in the process environment.

## Limits

`nblink` only dials out. It refuses inbound connections and does not reach the
host's own network, so the peer cannot become a route into the machine it runs
on.

Userspace mode carries TCP, UDP and ping only. It cannot act as an exit node or
a routing peer and does not take over system DNS. Ports below 1024 need
privileges the process usually does not have, though some container runtimes
lower that boundary.

This build forwards HTTP. The `tcp`, `udp` and `socks5` schemes are reserved by
the grammar and rejected with a message saying so, so adding them later needs
no change to how a forward is written.
