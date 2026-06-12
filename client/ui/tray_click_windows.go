//go:build windows

package main

// bindTrayClick wires the tray icon's click handlers on Windows.
//
// Wails v3's Windows systray leaves left-click a no-op (only right-click opens
// the menu), so bind OnClick to OpenMenu to match macOS/Linux. The macOS freeze
// that blocks OnClick→OpenMenu doesn't apply here: openMenu() is the same
// menu.ShowAt() path right-click already uses.
func bindTrayClick(t *Tray) {
	t.tray.OnClick(func() { t.tray.OpenMenu() })
	t.tray.OnDoubleClick(func() { t.ShowWindow() })
}
