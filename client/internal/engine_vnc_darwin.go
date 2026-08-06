//go:build darwin && !ios

package internal

import (
	"os"

	log "github.com/sirupsen/logrus"

	vncserver "github.com/netbirdio/netbird/client/vnc/server"
)

func newPlatformVNC() (vncserver.ScreenCapturer, vncserver.InputInjector, bool) {
	capturer := vncserver.NewMacPoller()
	// No permission request here. Screen Recording is a user-scope TCC service,
	// so a request from this process is dropped when it runs as a LaunchDaemon:
	// no prompt appears and NetBird never even shows up in the Screen Recording
	// list. The per-user agent asks instead, see newAgentResources.
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
