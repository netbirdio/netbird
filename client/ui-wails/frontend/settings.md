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

Friendly intro line on top: *"A debug bundle helps NetBird support investigate connection problems. It's a zip file with logs and system details from this device."*

Toggle rows:

- **Anonymize personal data** — `anonymize` · *toggle switch* · default **on**
  - Replace IPs, hostnames, and peer names before saving.
- **Include system info** — `systemInfo` · *toggle switch* · default **on**
  - Include OS, kernel, network interfaces, and routing tables.
- **Send to NetBird support** — *toggle switch* · default **off**
  - Uploads the bundle to a hardcoded NetBird endpoint (`NETBIRD_UPLOAD_URL` constant). On success the user gets a short upload key to share with support. Local copy is always kept too.
- **Capture detailed (trace) logs** — *toggle switch* · default **off**
  - Nested *Capture for [N] minutes* number input (1–30, suffix "min", default 3).
  - When enabled, the daemon's log level is switched to trace, NetBird is brought down and back up, the UI captures for the configured duration, the original log level is restored, then the bundle is created with `logFileCount: 5` (vs 1 in plain mode).
  - User-facing warning baked into the help text: "NetBird will briefly disconnect."

**Create bundle** — primary button. Disabled while running. Shows "Creating bundle…" label.

### Status / result block

Renders below the button while running and after completion.

- **Running** — bordered card with spinner + stage text. Stages: *Switching to trace logging…* → *Reconnecting NetBird…* → *Capturing logs — m:ss / m:ss* (countdown) → *Restoring previous log level…* → *Building bundle…* → *Uploading to NetBird…* (last only when upload toggle on; trace stages skipped when trace off).
- **Done — uploaded**: bordered card with the upload key in a copyable code block + "Share this key with NetBird support so they can find your bundle.". Below, a smaller card with the local path + Copy + Reveal (file://) buttons + admin-privilege note.
- **Done — local only**: single card with "Bundle saved to:" + path + Copy + Reveal + admin note.
- **Partial — upload failed**: red banner ("Upload failed: <reason>. The bundle is still saved locally.") above the local path card.
- **Error** (no bundle produced): red banner with the error message + a **Try again** button next to Create.

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
