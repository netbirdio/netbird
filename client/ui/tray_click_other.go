//go:build !windows && !android && !ios && !freebsd && !js

package main

func bindTrayClick(*Tray) {
	// No-op: macOS/Linux native trays open the menu on click themselves.
	// Only Windows needs an explicit handler (tray_click_windows.go).
}
