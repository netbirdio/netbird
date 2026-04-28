//go:build windows

package main

import _ "embed"

// Windows tray icons. Wails3 hands these to Shell_NotifyIcon via
// CreateIconFromResourceEx, which picks the frame matching SM_CXSMICON
// (16/32 px depending on DPI). A single high-res PNG forces the OS to
// downscale and the result is fuzzy at tray size — multi-frame .ico files
// avoid that by embedding 16/24/32/48 px raster frames in one resource.

//go:embed assets/netbird-systemtray-connected.ico
var winIconConnected []byte

//go:embed assets/netbird-systemtray-disconnected.ico
var winIconDisconnected []byte

//go:embed assets/netbird-systemtray-connecting.ico
var winIconConnecting []byte

//go:embed assets/netbird-systemtray-error.ico
var winIconError []byte

//go:embed assets/netbird-systemtray-update-connected.ico
var winIconUpdateConnected []byte

//go:embed assets/netbird-systemtray-update-disconnected.ico
var winIconUpdateDisconnected []byte
