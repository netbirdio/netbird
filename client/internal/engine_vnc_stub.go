//go:build (!windows && !darwin && !freebsd && !(linux && !android)) || (darwin && ios)

package internal

import vncserver "github.com/netbirdio/netbird/client/vnc/server"

func newPlatformVNC() (vncserver.ScreenCapturer, vncserver.InputInjector, bool) {
	return nil, nil, false
}

func vncNeedsServiceMode() bool {
	return false
}
