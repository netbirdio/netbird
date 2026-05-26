//go:build darwin

package main

import _ "embed"

// 22x22 status dot icons used on macOS. Apple's HIG recommends an
// 18–22 px glyph for NSMenuItem leading images; 22 matches the visual
// weight of the surrounding row text. Windows ships a 16x16 variant
// (Win32 SM_CXMENUCHECK slot) and Linux a 24x24 variant (GTK menu row
// supports the larger range) — see the sibling icons_menu_*.go files.
//
// iconMenuNetbird on macOS is an 18x18 downscale of the 256x256 brand
// PNG (assets/netbird.png — the same file the legacy Fyne client used
// for its About row). Sized to sit visually alongside the row text —
// the full 256x256 source stretched the row vertically, 22x22 read
// noticeably larger than the surrounding "A" of "About", and 14x14
// shrank below the cap height. 18 keeps the brand mark legible without
// dominating the row.

//go:embed assets/netbird-menu-about-18.png
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
