//go:build linux && !386

package main

import "os"

// init runs before Wails' own init(), so the env var is set in time.
func init() {
	if os.Getenv("WEBKIT_DISABLE_DMABUF_RENDERER") != "" {
		return
	}

	// WebKitGTK's DMA-BUF renderer fails on many setups (VMs, containers,
	// minimal WMs without proper GPU access) and leaves the window blank
	// white. Wails only disables it for NVIDIA+Wayland, but the issue is
	// broader. Always disable it — software rendering works fine for a
	// small UI like this.
	_ = os.Setenv("WEBKIT_DISABLE_DMABUF_RENDERER", "1")
}

// On Linux, the system tray provider may require the menu to be recreated
// rather than updated in place. The rebuildExitNodeMenu method in tray.go
// already handles this by removing and re-adding items; no additional
// Linux-specific workaround is needed for Wails v3.
