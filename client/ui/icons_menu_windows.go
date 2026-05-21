//go:build windows

package main

import _ "embed"

// 16x16 menu-row icons used on Windows. The Win32 SetMenuItemBitmaps API
// paints the HBITMAP into the check-mark slot, sized to SM_CXMENUCHECK /
// SM_CYMENUCHECK (typically 16x16 at 100% DPI). Larger bitmaps overflow
// the row visually, so Windows ships its own scaled set instead of the
// 24x24 assets used on macOS/Linux. Regenerate the brand mark from
// assets/svg/netbird-menu.svg (vector source — re-rendering keeps the
// strokes crisp at every target size):
//   inkscape assets/svg/netbird-menu.svg -o netbird-menu-16.png -w 16 -h 16 \
//     --export-background-opacity=0
// The status dots are downscaled from the 24x24 originals with
// ImageMagick — simple solid-fill circles survive the bicubic resize
// without visible quality loss:
//   magick netbird-menu-dot-<state>.png -resize 16x16 \
//     -background none -gravity center -extent 16x16 \
//     netbird-menu-dot-<state>-16.png

//go:embed assets/netbird-menu-16.png
var iconMenuNetbird []byte

//go:embed assets/netbird-menu-dot-connected-16.png
var iconMenuDotConnected []byte

//go:embed assets/netbird-menu-dot-connecting-16.png
var iconMenuDotConnecting []byte

//go:embed assets/netbird-menu-dot-login-16.png
var iconMenuDotLogin []byte

//go:embed assets/netbird-menu-dot-error-16.png
var iconMenuDotError []byte

//go:embed assets/netbird-menu-dot-idle-16.png
var iconMenuDotIdle []byte

//go:embed assets/netbird-menu-dot-offline-16.png
var iconMenuDotOffline []byte
