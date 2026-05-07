# Settings — Tabs & Controls

Each row has a title and short description. Booleans default to **toggle switch**; pick another control only when noted.

Tab order: **General · Network · Security · SSH · Advanced · Troubleshooting · About**.

---

## 1. General

App behavior + how the client connects.

### General

- **Connect on startup** — `disableAutoConnect` (inverted) · *toggle switch*
  - Automatically connect to NetBird when the app launches.
- **Show notifications** — `disableNotifications` (inverted) · *toggle switch*
  - Show desktop notifications for connection events and updates.

### Connection

- **Management Server** — `managementUrl` · *label + help text + (text input next to inline Save button)*
  - Help text sits between the label and the input. The NetBird management server this client connects to; saving reconnects to apply the new server. Save button persists explicitly (in addition to the global debounced auto-save) since changing the server triggers a reconnect.

---

## 2. Network

Routing and DNS — how the daemon reaches peers and resolves names.

### Connectivity

- **Lazy connections** — `lazyConnectionEnabled` · *toggle switch*
  - Only establish peer tunnels on first traffic instead of eagerly at startup.
- **Network monitor** — `networkMonitor` · *toggle switch*
  - Reconnect automatically when the host network changes (Wi-Fi switch, VPN, sleep/wake).

### Routing & DNS

- **Enable DNS** — `disableDns` (inverted) · *toggle switch*
  - Apply NetBird-managed DNS settings to the host resolver.
- **Enable client routes** — `disableClientRoutes` (inverted) · *toggle switch*
  - Accept routes advertised by other peers so this client can reach their networks.
- **Enable server routes** — `disableServerRoutes` (inverted) · *toggle switch*
  - Advertise this host's local routes to other peers.

---

## 3. Security

Firewall and on-the-wire encryption — what's blocked and how the tunnel is protected.

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

## 4. SSH

NetBird SSH server config. Master switch at the top; sub-toggles greyed out when the master is off.

### Server

- **Allow SSH** — `serverSshAllowed` · *toggle switch* (master)
  - Run the NetBird SSH server on this host so other peers can connect to it.

### Capabilities

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

## 5. Advanced

Power-user knobs: tunnel security, interface tuning, and log verbosity.

### Security

- **Pre-shared key** — `preSharedKey` · *label + help text + password input with reveal toggle*
  - Help text sits between the label and the input. Optional WireGuard pre-shared key for an extra layer of symmetric encryption; must match the value on every peer.

### Interface

- **Name** — `interfaceName` · *text input*
  - Name of the WireGuard network interface created on this host.
- **WireGuard Port** — `wireguardPort` · *number input*
  - Local UDP port the WireGuard interface listens on.
- **MTU** — `mtu` · *number input*
  - Maximum transmission unit for the WireGuard interface.

---

## 6. Troubleshooting

Everything you reach for when something is wrong.

### Debug bundle

- **Anonymize** — *toggle switch*
  - Strip IPs, hostnames, and peer names from the bundle before saving.
- **Include system info** — *toggle switch*
  - Add OS, kernel, and network interface details to the bundle.
- **Upload on create** — *toggle switch*
  - When on, reveals an upload URL field and uploads the bundle after creation.
- **Create Bundle** — *button* → progress indicator → resulting path or upload URL.

---

## 7. About

Two-row layout. Top row pairs the app icon with the product name + versions; everything else stacks below full-width.

**Top row** (icon left, info right):

1. **App icon** — `netbird-app-icon.svg`, `w-24 h-24`, rounded corners, subtle border (`border-nb-gray-800`).
2. **NetBird** heading + version lines:
   - **GUI v{x.y.z}** — from `frontend/package.json` at build time
   - **Client v{x.y.z}** — from `Status.daemonVersion`

**Below the top row**, in order:

3. **Update banner** *(visible only when an event in `Status.events` carries `metadata["new_version_available"]`)* — "Version X.Y.Z is available." + a **What's new?** link → GitHub release page for that version, plus a **Restart now** primary button → `Update.Trigger()`.
4. **Copyright** — "© {current year} NetBird. All Rights Reserved." (year from `new Date().getFullYear()`).
5. **Legal links** — Imprint · Privacy · CLA · Terms of Service. Each opens via Wails `Browser.OpenURL` with `window.open` fallback.
