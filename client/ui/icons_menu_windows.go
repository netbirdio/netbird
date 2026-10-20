//go:build windows

package main

import _ "embed"

// SetMenuItemBitmaps sizes the HBITMAP to SM_CXMENUCHECK/SM_CYMENUCHECK (16x16
// at 100% DPI); larger bitmaps overflow the row, hence this Windows-only set
// downscaled from the 24x24 originals.

//go:embed assets/netbird-menu-dot-connected-16.png
var iconMenuDotConnected []byte

//go:embed assets/netbird-menu-dot-connecting-16.png
var iconMenuDotConnecting []byte

//go:embed assets/netbird-menu-dot-error-16.png
var iconMenuDotError []byte

//go:embed assets/netbird-menu-dot-idle-16.png
var iconMenuDotIdle []byte

//go:embed assets/netbird-menu-dot-offline-16.png
var iconMenuDotOffline []byte
