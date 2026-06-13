# Linux tray support (StatusNotifierWatcher + XEmbed)

Minimal WMs (Fluxbox, OpenBox, i3, dwm, vanilla GNOME without the AppIndicator extension) don't ship a `StatusNotifierWatcher`, so tray icons using libayatana-appindicator / freedesktop StatusNotifier silently fail. `main.go` calls `startStatusNotifierWatcher()` *before* `NewTray` so the Wails systray's `RegisterStatusNotifierItem` call hits the in-process watcher we control.

- `tray_watcher_linux.go` — owns `org.kde.StatusNotifierWatcher` on the session bus if no other process has it. Safe to call unconditionally.
- `xembed_host_linux.go` + `xembed_tray_linux.{c,h}` — when an XEmbed tray (`_NET_SYSTEM_TRAY_S0`) is available, also start an in-process XEmbed host that bridges the SNI icon into the XEmbed tray. Reads `IconPixmap` over D-Bus, draws via cairo+X11, polls for clicks, fetches `com.canonical.dbusmenu.GetLayout` for the popup menu, fires `com.canonical.dbusmenu.Event` on click.

Build is gated on `linux && !386`; the 386 build (no cgo) and non-Linux builds use the `tray_watcher_other.go` no-op.
