//go:build linux && !(linux && 386)

package main

// bindTrayClick wires the tray icon's left-click handler on Linux.
//
// Both Linux click paths converge on Wails' linuxSystemTray.Activate, which
// fires the registered clickHandler:
//   - Real SNI hosts (KDE Plasma, Waybar, GNOME Shell + AppIndicator) invoke
//     org.kde.StatusNotifierItem.Activate over D-Bus on left-click.
//   - The in-process StatusNotifierWatcher + XEmbed host used on minimal WMs
//     (Fluxbox, i3, dwm, OpenBox) maps a Button1 press to that same Activate
//     call itself (xembed_host_linux.go), so it routes through the same hook.
// Registering OnClick here therefore covers both paths with one handler — no
// changes to the watcher or XEmbed C code are needed. Left-click now opens the
// main window; right-click still opens the menu via Wails' default
// SecondaryActivate→OpenMenu handler (and the XEmbed GTK popup on minimal WMs).
//
// We do NOT register OnDoubleClick: Wails' Linux SNI backend never fires it
// (unlike Windows). And we deliberately skip AttachWindow — it plus Wails3's
// applySmartDefaults would pop the window alongside the menu on GNOME Shell
// with the AppIndicator extension (see the bindTrayClick comment in tray.go).
//
// ShowWindow() is the same dispatcher the explicit "Open NetBird" menu entry
// and SIGUSR1 use: it brings the install-progress / browser-login window
// forward when one of those flows is active, otherwise routes through
// WindowManager.ShowMain so the window re-centers on minimal WMs / the XEmbed
// path instead of landing in the top-left corner.
func bindTrayClick(t *Tray) {
	t.tray.OnClick(func() { t.ShowWindow() })
}
