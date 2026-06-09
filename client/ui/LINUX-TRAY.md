# Linux tray support (StatusNotifierWatcher + XEmbed)

Minimal WMs (Fluxbox, OpenBox, i3, dwm, vanilla GNOME without the AppIndicator extension) don't ship a `StatusNotifierWatcher`, so tray icons using libayatana-appindicator / freedesktop StatusNotifier silently fail. `main.go` calls `startStatusNotifierWatcher()` *before* `NewTray` so the Wails systray's `RegisterStatusNotifierItem` call hits the in-process watcher we control.

- `tray_watcher_linux.go` — owns `org.kde.StatusNotifierWatcher` on the session bus if no other process has it. Safe to call unconditionally.
- `xembed_host_linux.go` + `xembed_tray_linux.{c,h}` — when an XEmbed tray (`_NET_SYSTEM_TRAY_S0`) is available, also start an in-process XEmbed host that bridges the SNI icon into the XEmbed tray. Reads `IconPixmap` over D-Bus, draws via cairo+X11, polls for clicks, fetches `com.canonical.dbusmenu.GetLayout` for the popup menu, fires `com.canonical.dbusmenu.Event` on click.

Build is gated on `linux && !386`; the 386 build (no cgo) and non-Linux builds use the `tray_watcher_other.go` no-op.

## Legacy GTK3 build (`-tags gtk3`)

The XEmbed host (`xembed_host_linux.go` + `xembed_tray_linux.{c,h}`) hard-links GTK4 and uses GTK4-only popup-menu APIs (`GdkSurface`, `GtkEventControllerFocus`, `gtk_window_set_child`, `gdk_display_get_monitors`→`GListModel`, …), so it cannot compile against GTK3. On the legacy `-tags gtk3` build those files are excluded (`//go:build … && !gtk3`) and `xembed_host_gtk3_linux.go` provides a pure-Go stub where `xembedTrayAvailable()` returns false. The watcher probe then exits immediately, so the in-process XEmbed fallback is **absent on GTK3 builds** — the tray works only where the desktop ships its own `StatusNotifierWatcher` (KDE, GNOME+AppIndicator, Cinnamon/xapp, XFCE), not on minimal WMs. Rather than port the ~150-line C menu layer to GTK3 we accept this gap; `-tags gtk3` is removed upstream in Wails v3.1.
