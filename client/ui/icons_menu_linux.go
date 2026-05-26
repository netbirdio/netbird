//go:build linux

package main

import _ "embed"

// 24x24 menu-row icons used on Linux. GTK4 menu rows accept icons in the
// 22–48 px range with no automatic downscaling at this size; 24 reads
// cleanly next to the row text across the GNOME / KDE / minimal-WM
// flavours we ship to. Windows ships a 16x16 variant (Win32
// SM_CXMENUCHECK slot) and macOS a 22x22 variant — see the sibling
// icons_menu_*.go files. Status dots are the canonical 24x24 originals
// used everywhere else in the legacy Fyne tray.

//go:embed assets/netbird-menu-dot-connected.png
var iconMenuDotConnected []byte

//go:embed assets/netbird-menu-dot-connecting.png
var iconMenuDotConnecting []byte

//go:embed assets/netbird-menu-dot-login.png
var iconMenuDotLogin []byte

//go:embed assets/netbird-menu-dot-error.png
var iconMenuDotError []byte

//go:embed assets/netbird-menu-dot-idle.png
var iconMenuDotIdle []byte

//go:embed assets/netbird-menu-dot-offline.png
var iconMenuDotOffline []byte
