//go:build darwin

package main

import _ "embed"

// 22px matches the NSMenuItem row text weight (HIG's 18-22 range);
// Windows uses 16px and Linux 24px — see the sibling icons_menu_*.go.

//go:embed assets/netbird-menu-dot-connected-22.png
var iconMenuDotConnected []byte

//go:embed assets/netbird-menu-dot-connecting-22.png
var iconMenuDotConnecting []byte

//go:embed assets/netbird-menu-dot-error-22.png
var iconMenuDotError []byte

//go:embed assets/netbird-menu-dot-idle-22.png
var iconMenuDotIdle []byte

//go:embed assets/netbird-menu-dot-offline-22.png
var iconMenuDotOffline []byte
