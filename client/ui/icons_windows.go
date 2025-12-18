package main

import (
	_ "embed"
)

//go:embed assets/netbird.ico
var iconAbout []byte

//go:embed assets/netbird-disconnected.ico
var iconAboutDisconnected []byte

//go:embed assets/netbird-systemtray-connected.ico
var iconConnected []byte

//go:embed assets/netbird-systemtray-connected-dark.ico
var iconConnectedDark []byte

//go:embed assets/netbird-systemtray-disconnected.ico
var iconDisconnected []byte

//go:embed assets/netbird-systemtray-update-disconnected.ico
var iconUpdateDisconnected []byte

//go:embed assets/netbird-systemtray-update-disconnected-dark.ico
var iconUpdateDisconnectedDark []byte

//go:embed assets/netbird-systemtray-update-connected.ico
var iconUpdateConnected []byte

//go:embed assets/netbird-systemtray-update-connected-dark.ico
var iconUpdateConnectedDark []byte

//go:embed assets/netbird-systemtray-connecting.ico
var iconConnecting []byte

//go:embed assets/netbird-systemtray-connecting-dark.ico
var iconConnectingDark []byte

//go:embed assets/netbird-systemtray-error.ico
var iconError []byte

//go:embed assets/netbird-systemtray-error-dark.ico
var iconErrorDark []byte
