//go:build linux && !android

package internal

import (
	"fmt"

	log "github.com/sirupsen/logrus"

	vncserver "github.com/netbirdio/netbird/client/vnc/server"
)

// newConsoleVNC builds a framebuffer + uinput VNC backend for boxes
// without a running X server. Used as the auto-fallback when
// newPlatformVNC can't reach X. Returns an error when /dev/fb0 or
// /dev/uinput aren't usable so the caller can drop back to a stub.
func newConsoleVNC() (vncserver.ScreenCapturer, vncserver.InputInjector, error) {
	poller := vncserver.NewFBPoller("")
	w, h := poller.Width(), poller.Height()
	if w == 0 || h == 0 {
		poller.Close()
		return nil, nil, fmt.Errorf("framebuffer capturer init failed (is /dev/fb0 readable?)")
	}
	inj, err := vncserver.NewUInputInjector(w, h)
	if err != nil {
		log.Debugf("uinput unavailable, falling back to view-only VNC: %v", err)
		return poller, &vncserver.StubInputInjector{}, nil
	}
	return poller, inj, nil
}
