//go:build windows

package internal

import vncserver "github.com/netbirdio/netbird/client/vnc/server"

func newPlatformVNC() (vncserver.ScreenCapturer, vncserver.InputInjector, bool) {
	return vncserver.NewDesktopCapturer(), vncserver.NewWindowsInputInjector(), true
}

func vncNeedsServiceMode() bool {
	return vncserver.GetCurrentSessionID() == 0
}
