//go:build darwin && !ios

package internal

import (
	"os"

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

// vncNeedsServiceMode reports whether the running process is a system
// LaunchDaemon (root, parented by launchd). Daemons sit in the global
// bootstrap namespace and cannot talk to WindowServer; we route capture
// through a per-user agent in that case.
func vncNeedsServiceMode() bool {
	return os.Geteuid() == 0 && os.Getppid() == 1
}
