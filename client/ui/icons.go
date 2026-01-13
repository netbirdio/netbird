//go:build !(linux && 386) && !windows

package main

import (
	_ "embed"
)

//go:embed assets/netbird.png
var iconAbout []byte

//go:embed assets/netbird-disconnected.png
var iconAboutDisconnected []byte

//go:embed assets/netbird-systemtray-connected.png
var iconConnected []byte

//go:embed assets/netbird-systemtray-connected-dark.png
var iconConnectedDark []byte

//go:embed assets/netbird-systemtray-disconnected.png
var iconDisconnected []byte

//go:embed assets/netbird-systemtray-update-disconnected.png
var iconUpdateDisconnected []byte

//go:embed assets/netbird-systemtray-update-disconnected-dark.png
var iconUpdateDisconnectedDark []byte

//go:embed assets/netbird-systemtray-update-connected.png
var iconUpdateConnected []byte

//go:embed assets/netbird-systemtray-update-connected-dark.png
var iconUpdateConnectedDark []byte

//go:embed assets/netbird-systemtray-connecting.png
var iconConnecting []byte

//go:embed assets/netbird-systemtray-connecting-dark.png
var iconConnectingDark []byte

//go:embed assets/netbird-systemtray-error.png
var iconError []byte

//go:embed assets/netbird-systemtray-error-dark.png
var iconErrorDark []byte
