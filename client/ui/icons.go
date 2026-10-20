//go:build !android && !ios && !freebsd && !js

package main

import _ "embed"

// Windows reuses these PNGs: multi-frame .ico never redrew under Wails3's NIM_MODIFY, single-frame PNG does.

//go:embed assets/netbird-systemtray-connected.png
var iconConnected []byte

//go:embed assets/netbird-systemtray-connected-dark.png
var iconConnectedDark []byte

//go:embed assets/netbird-systemtray-disconnected.png
var iconDisconnected []byte

//go:embed assets/netbird-systemtray-connecting.png
var iconConnecting []byte

//go:embed assets/netbird-systemtray-connecting-dark.png
var iconConnectingDark []byte

//go:embed assets/netbird-systemtray-error.png
var iconError []byte

//go:embed assets/netbird-systemtray-error-dark.png
var iconErrorDark []byte

//go:embed assets/netbird-systemtray-needs-login.png
var iconNeedsLogin []byte

//go:embed assets/netbird-systemtray-update-connected.png
var iconUpdateConnected []byte

//go:embed assets/netbird-systemtray-update-connected-dark.png
var iconUpdateConnectedDark []byte

//go:embed assets/netbird-systemtray-update-disconnected.png
var iconUpdateDisconnected []byte

//go:embed assets/netbird-systemtray-update-disconnected-dark.png
var iconUpdateDisconnectedDark []byte

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

// SNI has no template recoloring, so ship an explicit pair: black (*-mono.png)
// for light panels, white (*-mono-dark.png) for dark panels.

//go:embed assets/netbird-systemtray-connected-mono.png
var iconConnectedMono []byte

//go:embed assets/netbird-systemtray-connected-mono-dark.png
var iconConnectedMonoDark []byte

//go:embed assets/netbird-systemtray-connecting-mono.png
var iconConnectingMono []byte

//go:embed assets/netbird-systemtray-connecting-mono-dark.png
var iconConnectingMonoDark []byte

//go:embed assets/netbird-systemtray-disconnected-mono.png
var iconDisconnectedMono []byte

//go:embed assets/netbird-systemtray-disconnected-mono-dark.png
var iconDisconnectedMonoDark []byte

//go:embed assets/netbird-systemtray-error-mono.png
var iconErrorMono []byte

//go:embed assets/netbird-systemtray-error-mono-dark.png
var iconErrorMonoDark []byte

//go:embed assets/netbird-systemtray-needs-login-mono.png
var iconNeedsLoginMono []byte

//go:embed assets/netbird-systemtray-needs-login-mono-dark.png
var iconNeedsLoginMonoDark []byte

//go:embed assets/netbird-systemtray-update-connected-mono.png
var iconUpdateConnectedMono []byte

//go:embed assets/netbird-systemtray-update-connected-mono-dark.png
var iconUpdateConnectedMonoDark []byte

//go:embed assets/netbird-systemtray-update-disconnected-mono.png
var iconUpdateDisconnectedMono []byte

//go:embed assets/netbird-systemtray-update-disconnected-mono-dark.png
var iconUpdateDisconnectedMonoDark []byte

//go:embed assets/netbird.png
var iconWindow []byte

// Per-platform menu-row icons live in icons_menu_{windows,other}.go. Windows
// uses 16x16: they go into the Win32 check-mark slot (SM_CXMENUCHECK, ~16x16 at
// 100% DPI) which crops anything bigger; macOS/Linux use 24x24.
