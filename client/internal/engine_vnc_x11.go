//go:build (linux && !android) || freebsd

package internal

import (
	log "github.com/sirupsen/logrus"

	vncserver "github.com/netbirdio/netbird/client/vnc/server"
)

func newPlatformVNC() (vncserver.ScreenCapturer, vncserver.InputInjector, bool) {
	// Prefer X11 when an X server is reachable. NewX11InputInjector probes
	// DISPLAY (and /proc) eagerly.
	injector, err := vncserver.NewX11InputInjector("", "", "")
	if err == nil {
		return vncserver.NewX11Poller("", ""), injector, true
	}
	log.Debugf("VNC: X11 input injection unavailable: %v", err)

	// That failure covers two different things: no display at all, and a
	// display whose server has no XTest extension. Only the first rules X11
	// out. A host with a screen worth streaming and no way to inject input is
	// still better served by a view-only X11 session than by falling through
	// to a framebuffer console that is blank while X owns the VT.
	probe, capErr := vncserver.NewX11Capturer("", "")
	if capErr == nil {
		probe.Close()
		log.Infof("VNC: X11 capture available without input injection, serving view-only")
		return vncserver.NewX11Poller("", ""), &vncserver.StubInputInjector{}, true
	}
	log.Debugf("VNC: X11 capture unavailable: %v", capErr)

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
