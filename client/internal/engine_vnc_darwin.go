//go:build darwin && !ios

package internal

import (
	"os"

	log "github.com/sirupsen/logrus"

	vncserver "github.com/netbirdio/netbird/client/vnc/server"
)

func newPlatformVNC() (vncserver.ScreenCapturer, vncserver.InputInjector, bool) {
	capturer := vncserver.NewMacPoller()

	// Ask only when this process is the one that will capture. Screen Recording
	// is a user-scope TCC service, so the request is dropped from a
	// LaunchDaemon: no prompt appears and NetBird never even reaches the Screen
	// Recording list. In that case the per-user agent asks instead, see
	// newAgentResources.
	//
	// Without service mode there is no agent, so this process captures and
	// nothing else will ever raise the prompt — the client would serve a
	// windowless desktop with no indication why.
	if !vncNeedsServiceMode() {
		vncserver.RequestScreenRecording()
	}

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
