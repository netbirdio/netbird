//go:build !(linux && 386) && !windows

package main

import (
	_ "embed"
)

//go:embed netbird.png
var iconAbout []byte

//go:embed netbird-systemtray-connected.png
var iconConnected []byte

//go:embed netbird-systemtray-connected-dark.png
var iconConnectedDark []byte

//go:embed netbird-systemtray-disconnected.png
var iconDisconnected []byte

//go:embed netbird-systemtray-update-disconnected.png
var iconUpdateDisconnected []byte

//go:embed netbird-systemtray-update-disconnected-dark.png
var iconUpdateDisconnectedDark []byte

//go:embed netbird-systemtray-update-connected.png
var iconUpdateConnected []byte

//go:embed netbird-systemtray-update-connected-dark.png
var iconUpdateConnectedDark []byte

//go:embed netbird-systemtray-connecting.png
var iconConnecting []byte

//go:embed netbird-systemtray-connecting-dark.png
var iconConnectingDark []byte

//go:embed netbird-systemtray-error.png
var iconError []byte

//go:embed netbird-systemtray-error-dark.png
var iconErrorDark []byte
