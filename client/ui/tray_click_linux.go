//go:build linux

package main

// bindTrayClick wires the tray icon's left-click handler on Linux.
//
// Different StatusNotifierItem hosts route a left-click differently. KDE
// Plasma maps left-click to the SNI Activate method and right-click to the
// context menu — but NetBird wired no Activate action, so on KDE a left-click
// appeared completely dead while only right-click surfaced the menu (the
// behaviour users reported as confusing). Wails' Linux SNI backend forwards
// Activate to the tray's OnClick handler (systemtray_linux.go Activate →
// clickHandler), so we bind one here.
//
// We open the main window rather than the menu. OpenMenu() is not an option
// on Linux: the Wails v3 backend leaves linuxSystemTray.openMenu unimplemented
// (it only logs), so a left-click→OpenMenu binding would still do nothing on
// KDE. ShowWindow() is the same call Windows already runs from its
// double-click handler, so it is a proven-safe click-handler action — and it
// does not reproduce the macOS OpenMenu freeze (commit c77e5cef8): that freeze
// came from NSStatusItem's blocking embedded menu loop, whereas Show/Focus
// return immediately. The context menu stays reachable via right-click through
// the host's own rendering.
//
// On hosts where left-click already opens the menu natively (e.g. GNOME Shell
// with the AppIndicator extension) this means left-click now opens the window
// instead — the menu remains on right-click. AttachWindow is deliberately not
// used: combined with Wails3's applySmartDefaults it pops the window alongside
// the menu on those hosts, which is not the UX we want.
func bindTrayClick(t *Tray) {
	t.tray.OnClick(func() { t.ShowWindow() })
}
