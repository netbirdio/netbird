//go:build (linux && !android) || freebsd

package internal

import (
	log "github.com/sirupsen/logrus"

	vncserver "github.com/netbirdio/netbird/client/vnc/server"
)

func newPlatformVNC() (vncserver.ScreenCapturer, vncserver.InputInjector, bool) {
	// Prefer X11 when an X server is reachable. NewX11InputInjector probes
	// DISPLAY (and /proc) eagerly, so a non-nil error here means no X.
	injector, err := vncserver.NewX11InputInjector("", "", "")
	if err == nil {
		return vncserver.NewX11Poller("", ""), injector, true
	}
	log.Debugf("VNC: X11 not available: %v", err)

	// Fallback for headless / pre-X states (kernel console, login manager
	// without X, physical server in recovery): stream the framebuffer and
	// inject input via /dev/uinput.
	consoleCap, consoleInj, err := newConsoleVNC()
	if err == nil {
		log.Infof("VNC: using framebuffer console capture (%dx%d)", consoleCap.Width(), consoleCap.Height())
		return consoleCap, consoleInj, true
	}
	log.Debugf("VNC: framebuffer console fallback unavailable: %v", err)

	return &vncserver.StubCapturer{}, &vncserver.StubInputInjector{}, false
}

func vncNeedsServiceMode() bool {
	return false
}
