//go:build darwin

package main

import _ "embed"

// 22x22 menu-row icons used on macOS. Apple's HIG recommends an 18–22 px
// glyph for NSMenuItem leading images; 22 sits at the top of that range
// and matches the visual weight of the surrounding row text. Windows
// ships a 16x16 variant (Win32 SM_CXMENUCHECK slot) and Linux a 24x24
// variant (GTK menu row supports the larger range) — see the sibling
// icons_menu_*.go files.
//
// Regenerate the brand mark from assets/svg/netbird-menu.svg (vector
// source — re-rendering keeps the strokes crisp at every target size):
//   inkscape assets/svg/netbird-menu.svg -o netbird-menu-22.png -w 22 -h 22 \
//     --export-background-opacity=0
// Status dots are downscaled from the 24x24 originals with ImageMagick.

//go:embed assets/netbird-menu-22.png
var iconMenuNetbird []byte

//go:embed assets/netbird-menu-dot-connected-22.png
var iconMenuDotConnected []byte

//go:embed assets/netbird-menu-dot-connecting-22.png
var iconMenuDotConnecting []byte

//go:embed assets/netbird-menu-dot-login-22.png
var iconMenuDotLogin []byte

//go:embed assets/netbird-menu-dot-error-22.png
var iconMenuDotError []byte

//go:embed assets/netbird-menu-dot-idle-22.png
var iconMenuDotIdle []byte

//go:embed assets/netbird-menu-dot-offline-22.png
var iconMenuDotOffline []byte
