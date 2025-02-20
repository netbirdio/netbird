package main

import (
 _ "embed"
)

//go:embed netbird.ico
var iconAbout []byte

//go:embed netbird-systemtray-connected.ico
var iconConnected []byte

//go:embed netbird-systemtray-connected-dark.ico
var iconConnectedDark []byte

//go:embed netbird-systemtray-disconnected.ico
var iconDisconnected []byte

//go:embed netbird-systemtray-update-disconnected.ico
var iconUpdateDisconnected []byte

//go:embed netbird-systemtray-update-disconnected-dark.ico
var iconUpdateDisconnectedDark []byte

//go:embed netbird-systemtray-update-connected.ico
var iconUpdateConnected []byte

//go:embed netbird-systemtray-update-connected-dark.ico
var iconUpdateConnectedDark []byte

//go:embed netbird-systemtray-connecting.ico
var iconConnecting []byte

//go:embed netbird-systemtray-connecting-dark.ico
var iconConnectingDark []byte

//go:embed netbird-systemtray-error.ico
var iconError []byte

//go:embed netbird-systemtray-error-dark.ico
var iconErrorDark []byte
