//go:build windows

package main

import "strings"

// trayIcon returns the Windows-tray .ico bytes for the given state. The
// other-platform implementation in tray_icon_other.go returns the colored
// PNG instead. Splitting it this way keeps the Linux/macOS paths free of
// .ico artifacts in their //go:embed search and avoids loading large icon
// resources where they aren't used.
func trayIcon(connected, hasUpdate bool, statusLabel string) []byte {
	switch {
	case strings.EqualFold(statusLabel, "Connecting"):
		return winIconConnecting
	case strings.EqualFold(statusLabel, "Error"):
		return winIconError
	case connected && hasUpdate:
		return winIconUpdateConnected
	case connected:
		return winIconConnected
	case hasUpdate:
		return winIconUpdateDisconnected
	default:
		return winIconDisconnected
	}
}
