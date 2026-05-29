//go:build windows

package main

// bindTrayClick wires the tray icon's left-click to open the menu on Windows.
//
// Unlike macOS (NSStatusItem auto-shows the menu on left-click) and Linux
// (the StatusNotifierItem host paints the menu itself), Wails v3's Windows
// systray installs a default left-click handler that only logs "Left Button
// Clicked" and does nothing visible — only right-click opens the menu via the
// default rightClickHandler (see systemtray_windows.go run()). Left-clicking
// the icon therefore appears dead to the user. We bind OnClick to OpenMenu so
// left- and right-click behave identically, matching the platform-native
// click→menu behaviour we get for free on macOS/Linux.
//
// The macOS freeze that motivated reverting an earlier OnClick→OpenMenu wiring
// (commit c77e5cef8: NSStatusItem's blocking [button mouseDown:] starves the
// serial main GCD queue) does not apply here — the Windows openMenu() path is
// the same menu.ShowAt() that right-click already uses without issue.
func bindTrayClick(t *Tray) {
	t.tray.OnClick(func() { t.tray.OpenMenu() })
}
