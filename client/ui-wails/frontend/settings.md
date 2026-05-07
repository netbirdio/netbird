# Settings — Tabs & Controls

Each row has a title and short description. Booleans default to **toggle switch**; pick another control only when noted.

Tab order: **General · Network · SSH · Troubleshooting · About**.

---

## 1. General

App behavior + how the client connects.

### Startup

- **Connect on startup** — `disableAutoConnect` (inverted) · *toggle switch*
  - Automatically connect to NetBird when the app launches.
- **Show notifications** — `disableNotifications` (inverted) · *toggle switch*
  - Show desktop notifications for connection events and updates.

### Connection

- **Management URL** — `managementUrl` · *text input*
  - The NetBird management server this client connects to.
- **Admin URL** — `adminUrl` · *text input*
  - Web dashboard URL used by "Open Admin Panel".
- **Pre-shared key** — `preSharedKey` · *password input with reveal toggle*
  - Optional WireGuard pre-shared key for an extra layer of symmetric encryption.

### Interface

- **Interface name** — `interfaceName` · *text input*
  - Name of the WireGuard network interface created on this host.
- **WireGuard port** — `wireguardPort` · *number input*
  - Local UDP port the WireGuard interface listens on.
- **MTU** — `mtu` · *number input*
  - Maximum transmission unit for the WireGuard interface.

---

## 2. Network

Routing, DNS, firewall, and encryption — everything the daemon does on the wire and to the host network.

### Routing & DNS

- **Lazy connections** — `lazyConnectionEnabled` · *toggle switch*
  - Only establish peer tunnels on first traffic instead of eagerly at startup.
- **Network monitor** — `networkMonitor` · *toggle switch*
  - Reconnect automatically when the host network changes (Wi-Fi switch, VPN, sleep/wake).
- **Enable DNS** — `disableDns` (inverted) · *toggle switch*
  - Apply NetBird-managed DNS settings to the host resolver.
- **Enable client routes** — `disableClientRoutes` (inverted) · *toggle switch*
  - Accept routes advertised by other peers so this client can reach their networks.
- **Enable server routes** — `disableServerRoutes` (inverted) · *toggle switch*
  - Advertise this host's local routes to other peers.

### Firewall

- **Block inbound traffic** — `blockInbound` · *toggle switch*
  - Drop all unsolicited inbound traffic on the NetBird interface.
- **Block LAN access** — `blockLanAccess` · *toggle switch*
  - Prevent peers from reaching this host's local network.

### Encryption

- **Quantum-resistant encryption** — `rosenpassEnabled` · *toggle switch*
  - Add a post-quantum key exchange (Rosenpass) on top of WireGuard.
  - **Permissive mode** — `rosenpassPermissive` · *toggle switch* (nested, only when above is on)
    - Allow connections to peers without quantum-resistance support.

---

## 3. SSH

NetBird SSH server config. Master switch at the top; sub-toggles greyed out with an inline notice ("Enable Allow SSH to configure") when the master is off.

### Server

- **Allow SSH** — `serverSshAllowed` · *toggle switch* (master)
  - Run the NetBird SSH server on this host so other peers can connect to it.
- **Allow root login** — `enableSshRoot` · *toggle switch*
  - Permit incoming SSH sessions to authenticate as `root`.
- **Enable SFTP** — `enableSshSftp` · *toggle switch*
  - Allow file transfers over the NetBird SSH server.
- **Local port forwarding** — `enableSshLocalPortForwarding` · *toggle switch*
  - Allow clients to forward local ports through this host.
- **Remote port forwarding** — `enableSshRemotePortForwarding` · *toggle switch*
  - Allow clients to expose remote ports back through this host.

### Authentication

- **Disable SSH auth** — `disableSshAuth` · *toggle switch*
  - Skip JWT authentication for incoming SSH sessions. **Insecure — diagnostics only.**
- **JWT cache TTL** — `sshJwtCacheTtl` · *number input (seconds)*
  - How long verified JWTs are cached before re-validation.

---

## 4. Troubleshooting

Everything you reach for when something is wrong. Config + actions deliberately mixed — they're used together.

### Logging

- **Log level** — *dropdown: Debug / Info / Warn / Error*
  - Verbosity of the daemon log. Raise to Debug when reproducing an issue.
- **Log file path** — *read-only text + Copy + Reveal in Finder/Explorer*
- **Config file path** — *read-only text + Copy + Reveal in Finder/Explorer*

### Debug bundle

- **Anonymize** — *toggle switch*
  - Strip IPs, hostnames, and peer names from the bundle before saving.
- **Include system info** — *toggle switch*
  - Add OS, kernel, and network interface details to the bundle.
- **Upload on create** — *toggle switch*
  - When on, reveals an upload URL field and uploads the bundle after creation.
- **Create Bundle** — *button* → progress indicator → resulting path or upload URL.

---

## 5. About

Version, update flow, and identity reference.

- App version, daemon version
- **Check for Updates** — *button* (drives auto-update flow; 15-min timeout, success/error states)
- Local peer info quick-reference (FQDN, IP) — same data shown in the connection-state view
- Links: docs, GitHub repo, license
