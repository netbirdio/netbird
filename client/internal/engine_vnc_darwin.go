//go:build darwin && !ios

package internal

import (
	log "github.com/sirupsen/logrus"

	vncserver "github.com/netbirdio/netbird/client/vnc/server"
)

func newPlatformVNC() (vncserver.ScreenCapturer, vncserver.InputInjector, bool) {
	capturer := vncserver.NewMacPoller()
	// Prompt for Screen Recording at server-enable time rather than first
	// client-connect. The native prompt is far easier for users to act on
	// in the moment they toggled VNC on than later when "the screen looks
	// like wallpaper" would otherwise be the only clue.
	vncserver.PrimeScreenCapturePermission()
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
