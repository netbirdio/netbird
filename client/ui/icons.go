//go:build !android && !ios && !freebsd && !js

package main

import _ "embed"

// Tray icons embedded from the legacy Fyne UI's asset set. Each pair is a
// light-mode PNG and its dark-mode variant; macOS template variants
// (*-macos.png) live alongside for menubar use. Windows uses the same
// PNGs — multi-resolution .ico files looked promising on disk but
// Wails3's Shell_NotifyIcon NIM_MODIFY never redrew them on the running
// tray; PNG single-frame works.

//go:embed assets/netbird-systemtray-connected.png
var iconConnected []byte

//go:embed assets/netbird-systemtray-connected-dark.png
var iconConnectedDark []byte

//go:embed assets/netbird-systemtray-disconnected.png
var iconDisconnected []byte

//go:embed assets/netbird-systemtray-connecting.png
var iconConnecting []byte

//go:embed assets/netbird-systemtray-error.png
var iconError []byte

//go:embed assets/netbird-systemtray-needs-login.png
var iconNeedsLogin []byte

//go:embed assets/netbird-systemtray-update-connected.png
var iconUpdateConnected []byte

//go:embed assets/netbird-systemtray-update-disconnected.png
var iconUpdateDisconnected []byte

//go:embed assets/netbird-systemtray-connected-macos.png
var iconConnectedMacOS []byte

//go:embed assets/netbird-systemtray-disconnected-macos.png
var iconDisconnectedMacOS []byte

//go:embed assets/netbird-systemtray-connecting-macos.png
var iconConnectingMacOS []byte

//go:embed assets/netbird-systemtray-error-macos.png
var iconErrorMacOS []byte

//go:embed assets/netbird-systemtray-needs-login-macos.png
var iconNeedsLoginMacOS []byte

//go:embed assets/netbird-systemtray-update-connected-macos.png
var iconUpdateConnectedMacOS []byte

//go:embed assets/netbird-systemtray-update-disconnected-macos.png
var iconUpdateDisconnectedMacOS []byte

//go:embed assets/netbird.png
var iconWindow []byte
