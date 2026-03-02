//go:build !(linux && 386)

package main

import _ "embed"

//go:embed assets/netbird-systemtray-disconnected.png
var iconDisconnected []byte

//go:embed assets/netbird-systemtray-connected.png
var iconConnected []byte

//go:embed assets/netbird-systemtray-connecting.png
var iconConnecting []byte

//go:embed assets/netbird-systemtray-error.png
var iconError []byte

// iconForStatus returns the appropriate tray icon bytes for the given status string.
func iconForStatus(status string) []byte {
	switch status {
	case "Connected":
		return iconConnected
	case "Connecting":
		return iconConnecting
	case "Disconnected", "":
		return iconDisconnected
	default:
		return iconError
	}
}
