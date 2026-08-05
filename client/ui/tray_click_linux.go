//go:build linux && !(linux && 386)

package main

// bindTrayClick wires the tray icon's left-click handler on Linux.
//
// Expected behaviour per tray host:
//
//	Host                           Left click              Right click
//	KDE Plasma, Waybar             main window (Activate)  menu (host-rendered)
//	GNOME Shell + AppIndicator     menu only               menu only
//	Minimal WMs via XEmbed host    main window (Activate)  XEmbed GTK popup
//
// OnClick fires only on org.kde.StatusNotifierItem.Activate — a real left
// click. KDE/Waybar send it over D-Bus; the in-process XEmbed host
// (xembed_host_linux.go) maps a Button1 press to the same Activate call.
//
// GNOME Shell + AppIndicator never sends Activate: it renders the dbusmenu
// on ANY click and only reports the menu opening via dbusmenu
// Event("opened"). Upstream Wails treated that event as a click, so on GNOME
// both buttons raised the main window on top of the menu, and on KDE/Waybar
// a right click raised it over the freshly opened menu. The netbirdio/wails
// fork (go.mod replace) drops that heuristic: a menu open never fires
// OnClick. On GNOME the main window is reached via the "Open NetBird" menu
// entry; left-click-opens-window is not achievable there anyway, since the
// host always opens the menu itself.
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
