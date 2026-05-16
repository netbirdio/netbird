//go:build darwin && !ios

package internal

import (
	log "github.com/sirupsen/logrus"

	vncserver "github.com/netbirdio/netbird/client/vnc/server"
)

func newPlatformVNC() (vncserver.ScreenCapturer, vncserver.InputInjector, bool) {
	capturer := vncserver.NewMacPoller()
	injector, err := vncserver.NewMacInputInjector()
	if err != nil {
		log.Debugf("VNC: macOS input injector: %v", err)
		return capturer, &vncserver.StubInputInjector{}, true
	}
	return capturer, injector, true
}

func vncNeedsServiceMode() bool {
	return false
}
