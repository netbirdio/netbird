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
docker run --rm -p 127.0.0.1:8080:8080 \
  --mount type=bind,src="$(pwd)/nb_setup_key",dst=/run/secrets/nb_setup_key,readonly \
  -e NB_SETUP_KEY=file:/run/secrets/nb_setup_key \
  -e NB_FORWARD='http://0.0.0.0:8080=https://grafana.internal' \
  -e NB_ALLOW_PUBLIC_BIND=true \
  netbirdio/nblink
```

The key file has to exist before the run and be readable by the container
user, which is UID 65532 in group 0. A bind mount keeps the host file's owner
and mode, so a root-owned key written with the usual `chmod 600` is not
readable and the run fails on startup with `permission denied`. Either give the
file to that UID (`chown 65532`) or keep it mode `640` in group 0
(`chgrp 0`). If the source path does not exist, `--mount` refuses to start the
container; the older `-v` form creates a directory there instead, which the read
then reports as a directory.

The image needs no `--privileged`, no `--cap-add NET_ADMIN`, no
`--device /dev/net/tun` and no host networking.

Inside a container the listener has to bind `0.0.0.0`, because a published
port arrives on the container's own interface rather than its loopback. That
still requires `NB_ALLOW_PUBLIC_BIND`, so exposing a forward is always
something the operator wrote down. Publish it on the host's loopback as above:
a bare `-p 8080:8080` publishes on every host interface, which hands the
peer's identity to anyone on the network who can reach the port.

A public listener accepts requests addressed to `localhost` or to an IP
address. Any name other machines use to reach it, such as a DNS name or a
Kubernetes Service name, has to be listed with `--allowed-host`
(`NB_ALLOWED_HOST`). See [Limits](#limits) for why.

The image keeps its state in memory, so it runs on a read-only root filesystem
and each start registers a new peer. To keep one identity across restarts, set
`NB_STATE_DIR=/var/lib/nblink` and mount a volume there:

```sh
docker run --rm --read-only -p 127.0.0.1:8080:8080 \
  -v nblink-state:/var/lib/nblink -e NB_STATE_DIR=/var/lib/nblink \
  ...
```

Without a state directory, use an ephemeral setup key so the peers left behind
by earlier starts are removed once they go offline, rather than piling up.

## Kubernetes and OpenShift

The image fits OpenShift's `restricted-v2` SCC and the Kubernetes `restricted`
Pod Security Standard as it is:

- It runs as any UID. OpenShift assigns one from the namespace range and adds
  group 0, and everything the process writes is owned by group 0.
- It needs no capabilities, no privilege escalation, no TUN device and no host
  networking, so `capabilities: {drop: [ALL]}` and
  `allowPrivilegeEscalation: false` hold.
- With state in memory it needs no writable path, so
  `readOnlyRootFilesystem: true` holds.

The simplest shape is a sidecar. The application in the same pod reaches the
forward on `localhost`, so the listener stays on loopback and needs neither
`NB_ALLOW_PUBLIC_BIND` nor a Service:

```yaml
containers:
  - name: nblink
    image: netbirdio/nblink
    env:
      - name: NB_FORWARD
        value: http://8080=https://grafana.internal
      - name: NB_SETUP_KEY
        value: file:/run/secrets/nblink/setup-key
    volumeMounts:
      - name: nblink-key
        mountPath: /run/secrets/nblink
        readOnly: true
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      capabilities: {drop: [ALL]}
      seccompProfile: {type: RuntimeDefault}
volumes:
  - name: nblink-key
    secret:
      secretName: nblink-setup-key
      defaultMode: 0440
```

A Secret volume is owned by the pod's `fsGroup`, which OpenShift sets for
every pod, so mode `0440` is readable by the container and by nothing else.

To keep the identity across pod restarts, mount a persistent volume at
`/var/lib/nblink` and set `NB_STATE_DIR` to it. `fsGroup` makes the volume
writable by the arbitrary UID. A `Deployment` with more than one replica
cannot share one state directory: every replica is its own peer, so give
each one its own volume through a `StatefulSet`, or keep state in memory with
an ephemeral setup key.

Serving a forward to other pods through a Service needs `NB_ALLOW_PUBLIC_BIND`
and every name callers use in `NB_ALLOWED_HOST`, for example
`grafana-link,grafana-link.monitoring.svc,grafana-link.monitoring.svc.cluster.local`.
Each caller acts under the forwarder peer's identity, so restrict who can
reach the Service with a `NetworkPolicy`. Do not expose it through a Route or
an Ingress.

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
| `--allowed-host` | `NB_ALLOWED_HOST` | | Extra name a listener accepts in `Host`, repeatable. Comma separated in the environment. |
| `--no-browser` | `NB_NO_BROWSER` | `false` | Print the login URL instead of opening a browser. |
| `--check` | `NB_CHECK` | `false` | Validate, print the effective forwards, exit. |

A secret given as `file:/path` is read from that file, so a container can mount
it instead of exposing it in the process environment.

## Limits

`nblink` only dials out. It refuses inbound connections and does not reach the
host's own network, so the peer cannot become a route into the machine it runs
on.

A loopback forward answers only requests whose `Host` names the loopback
interface or a name listed with `--allowed-host`, and refuses any request a
browser marks as belonging to another page, through either a cross-origin
`Origin` or a cross-site `Sec-Fetch-Site`. A page the user visits can point its
own hostname at `127.0.0.1` or embed the address directly, and without those
checks the browser could reach the upstream through this listener under the
peer's identity. Ordinary callers send neither header and are unaffected.

A public forward applies the same checks, and also accepts any IP address in
`Host`, since a page cannot rebind an address. The `Host` check matters there
too: a container port published on the host's loopback is reached by a
rebound page with a matching `Origin`, and its unlisted name is the only thing
that gives it away.

A name listed with `--allowed-host` is trusted rather than merely permitted,
and the list applies to every forward in the process, loopback ones included.
`Host` is the one signal a rebound page cannot forge, and listing a name gives
that up for it: a page served on that name can resolve it to the listener and
send a matching `Host` and `Origin`, which the browser then marks same-origin.
List only names you control, and prefer a fully qualified one, since a
single-label name can be answered by anything on the local network.

A forward on `0.0.0.0` listens on IPv4 only, and one on `::` on IPv6 only.

`nblink` does not ask the local router for a port mapping through UPnP,
NAT-PMP or PCP, since an unprivileged forwarder should not reconfigure the
network it runs on. Connections are still established through hole punching
or the relay. Set `NB_DISABLE_NAT_MAPPER=false` to allow it.

A browser too old to send `Sec-Fetch-Site`, which browsers have sent since
2020, can still reach a loopback forward with an embedded no-cors GET.

Userspace mode carries TCP, UDP and ping only. It cannot act as an exit node or
a routing peer and does not take over system DNS. Ports below 1024 need
privileges the process usually does not have, though some container runtimes
lower that boundary.

This build forwards HTTP. The `tcp`, `udp` and `socks5` schemes are reserved by
the grammar and rejected with a message saying so, so adding them later needs
no change to how a forward is written.
