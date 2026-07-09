//go:build windows

package main

// Open application window on left click, right click opens the tray menu
func bindTrayClick(t *Tray) {
	t.tray.OnClick(func() { t.ShowWindow() })
}
