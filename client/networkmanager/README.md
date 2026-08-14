# NetworkManager plugin for NetBird

A NetworkManager VPN plugin so NetBird shows up as a native VPN connection
type (`nmcli`, GNOME Settings, `nm-connection-editor`) instead of relying on
`netbird-ui`. It is a thin control-plane front end: it drives the real
`netbird` daemon's gRPC API to log in (including browser-based SSO) and to
connect/disconnect, while the daemon itself keeps owning the tunnel
interface, routes, DNS, and firewall exactly as it does today.

Linux-only. Not part of a release; build and install it locally.

## Layout

- `cmd/nm-netbird-service` — the VPN service NetworkManager spawns per
  active connection. Pure Go, implements
  `org.freedesktop.NetworkManager.VPN.Plugin` directly over D-Bus.
- `cmd/nm-netbird-auth-dialog` — the interactive helper NetworkManager
  spawns in your desktop session for SSO login. Hand-written C/GTK4 (via
  cgo) rather than a generated Go binding, since the latest `gotk4` release
  fails to compile against current GLib.
- `properties/` — the connection-editor plugin (`nm-connection-editor`/GNOME
  Settings support), split into a toolkit-independent core `.so` and two
  separate GTK3/GTK4 editor `.so`s, matching how NetworkManager's own
  bundled plugins (openvpn, vpnc, ...) are structured. Both variants exist
  because `nm-connection-editor` is still GTK3 on some distributions even
  where GTK4 is the default elsewhere (GNOME Settings' own network panel is
  GTK4) — the core plugin detects which toolkit is already loaded in the
  host process and dlopen's the matching editor at runtime, never both.
- `udev/` — marks netbird's tunnel interface unmanaged by NetworkManager,
  see [Known issues](#known-issues).
- `selinux/` — a local policy module needed on SELinux-enforcing systems
  (Fedora and friends), see [SELinux](#selinux).

## Prerequisites

Go pieces need nothing beyond what building netbird already needs (the
auth-dialog uses cgo against libgtk-4 directly, not a Go binding). The
editor plugin additionally needs both GTK3 and GTK4 dev headers:

```
# Fedora
sudo dnf install NetworkManager-libnm-devel gtk4-devel gtk3-devel glib2-devel

# Debian/Ubuntu
sudo apt install libnm-dev libgtk-4-dev libgtk-3-dev libglib2.0-dev
```

## Build and install

```
cd client/networkmanager
make
sudo make install
```

`make` fails loudly (not silently) if `libnm`/`gtk4`/`glib2` dev packages
are missing. To build only the two Go binaries without those packages
installed:

```
make SKIP_PROPERTIES=1
sudo make install SKIP_PROPERTIES=1
```

`make install` installs:

| What | Where |
|---|---|
| `nm-netbird-service`, `nm-netbird-auth-dialog` | `/usr/libexec` |
| `libnm-vpn-plugin-netbird.so`, `libnm-vpn-plugin-netbird-editor.so` (GTK3), `libnm-gtk4-vpn-plugin-netbird-editor.so` (GTK4) | `libdir/NetworkManager` (e.g. `/usr/lib64/NetworkManager`) |
| `nm-netbird-service.name` | libnm's `vpnservicedir` (e.g. `/usr/lib/NetworkManager/VPN`) |
| `nm-netbird-service.conf` | `/etc/dbus-1/system.d` |
| `71-nm-unmanaged-netbird.rules` | `/usr/lib/udev/rules.d` |

`sudo make uninstall` removes all of the above, including the udev rule —
that rule (see [Known issues](#known-issues)) is only meant to apply while
this plugin is actually installed, not linger after. If you also installed
the SELinux module, remove it separately: `sudo semodule -r nm_netbird_local`
(or `sudo make -C selinux uninstall`).

After installing for the first time, restart NetworkManager so it picks up
the new plugin and D-Bus policy:

```
sudo systemctl restart NetworkManager
```

### SELinux

On SELinux-enforcing systems (Fedora and derivatives), the targeted policy
has no dedicated domain for this plugin the way it does for `nm-openvpn`,
so `nm-netbird-service` runs under `NetworkManager_t` and is denied access
to the netbird daemon's control socket by default. Without this, connecting
fails with `dial unix /var/run/netbird.sock: connect: permission denied` in
`journalctl -u NetworkManager`. `make install` detects `Enforcing` mode and
prints a reminder; to fix it:

```
cd client/networkmanager/selinux
make
sudo make install
```

This installs a small local policy module (`selinux/nm_netbird_local.te`)
granting exactly the two denied operations (reading/writing the daemon's
socket file, and connecting to the daemon's process domain) — nothing
broader. Inspect the `.te` file before installing it; it's short.

## Usage

Create a connection (SSO login, no setup key):

```
nmcli connection add type vpn vpn-type netbird ifname -- \
  vpn.data "management-url=https://your-management-server:443" \
  connection.id my-netbird
nmcli connection up my-netbird
```

Or use the GTK4 editor via GNOME Settings / `nm-connection-editor` → Add
VPN → NetBird, if `properties/` was built and installed.

`vpn.data` keys map to `netbird up` flags: `management-url`, `admin-url`,
`interface-name`, `hostname`, `mtu`, `wireguard-port`, `block-inbound`,
`disable-server-routes`, `block-lan-access`, `disable-client-routes`,
`disable-dns`, `disable-firewall`, `disable-ipv6`, `rosenpass-enabled`,
`rosenpass-permissive`, `disable-auto-connect`, `network-monitor` (booleans
are the strings `yes`/`no`). `setup-key` is a secret
(`vpn.secrets`); leave it empty to use SSO instead.

## Known issues

- **NetworkManager may show netbird's tunnel interface (`wt0` by default)
  as a second, bare device** in GNOME's network UI, since netbird creates
  and manages it directly rather than through NetworkManager. The udev
  rule in `udev/` marks it unmanaged to prevent this — if you changed
  `interface-name` away from the default `wt0`, edit the rule to match.
- **Disconnect through NetworkManager, not around it.** Once a connection
  is active, use `nmcli connection down`/GNOME's network menu rather than
  `netbird down` or `netbird-ui` directly. NetworkManager's VPN state
  machine (`nm-vpn-connection.c`) unconditionally treats an unprompted
  "stopped" report as a *failure* when it still believes the connection is
  active — there is no D-Bus signal that means "stopped gracefully but you
  didn't ask": it's a hard constraint of NM's model (the same thing would
  happen if any VPN's underlying process died unexpectedly), not something
  this plugin can special-case around. It still correctly syncs
  NetworkManager's state either way; expect a "connection failed"
  notification, not a stuck "connected" state, when bypassing NM this way.
- No automated test suite: this is host-networking, D-Bus, and GTK
  integration code that's only meaningfully verified against a real
  daemon and a running NetworkManager/GNOME session.
