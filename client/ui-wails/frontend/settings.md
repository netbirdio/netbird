1. General

The "old tray" toggles + notifications. This is what 90% of users come to Settings for.

- Connect on startup — disableAutoConnect (inverted)
- Allow SSH — serverSshAllowed (master switch; the SSH tab is the detail)
- Quantum-resistance — rosenpassEnabled
    - Nested when on: Permissive mode — rosenpassPermissive
- Lazy connections — lazyConnectionEnabled
- Block inbound — blockInbound
- Show notifications — disableNotifications (inverted)

▎ Note: blockInbound is technically a firewall behavior, but Stage 1 explicitly groups it with the tray-replacement toggles. Keep it here.

2. Connection

Identity + how the wire is established. The "what server am I talking to and how" tab.

- Management URL — managementUrl
- Pre-shared key — preSharedKey (password input, toggle reveal)
- Advanced (collapsed by default)
    - Admin URL — adminUrl
    - Interface name — interfaceName
    - WireGuard port — wireguardPort
    - MTU — mtu

3. Network

Routing / DNS / LAN behavior — i.e. what the daemon does to the host network.

- Network monitor — networkMonitor
- Disable DNS — disableDns
- Disable client routes — disableClientRoutes
- Disable server routes — disableServerRoutes
- Block LAN access — blockLanAccess

4. SSH

Detailed SSH server config. Greyed out with an inline notice ("Enable Allow SSH in General to configure") when serverSshAllowed is off.

- SSH root login — enableSshRoot
- SFTP — enableSshSftp
- Local port forwarding — enableSshLocalPortForwarding
- Remote port forwarding — enableSshRemotePortForwarding
- Advanced (collapsed)
    - Disable SSH auth — disableSshAuth
    - JWT cache TTL — sshJwtCacheTtl

5. Diagnostics

Everything you reach for when something is wrong. Mixes config (log level) with actions (bundle creation) deliberately — they're used together.

- Log level — Debug / Info / Warn / Error (dropdown)
- Log file path — read-only, with Copy + Reveal in Finder/Explorer buttons (configFile / logFile from daemon)
- Config file path — same pattern
- Debug bundle (own section)
    - Anonymize toggle
    - Include system info toggle
    - Upload on create toggle → reveals URL field when on
    - Create Bundle button → progress indicator → resulting path or upload URL displayed below

6. About

Version + update flow + identity reference.

- App version, daemon version
- Check for Updates button → drives the auto-update flow (15-min timeout, success/error states)
- Local peer info quick-reference (FQDN, IP) — same data the connection-state view shows
- Links: docs, GitHub repo, license
