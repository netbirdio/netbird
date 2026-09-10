//go:build freebsd

package internal

import (
	"fmt"

	log "github.com/sirupsen/logrus"

	vncserver "github.com/netbirdio/netbird/client/vnc/server"
)

// newConsoleVNC builds the FreeBSD console fallback: the vt(4) framebuffer for
// capture, and no input.
//
// Input injection is not implemented on FreeBSD: the uinput injector is a
// Linux-only implementation built on UI_DEV_CREATE and friends, so this backend
// mirrors the console read-only. It is offered anyway because a view-only
// console is still worth more than nothing on a box with no X server.
func newConsoleVNC() (vncserver.ScreenCapturer, vncserver.InputInjector, error) {
	poller := vncserver.NewFBPoller("")
	w, h := poller.Width(), poller.Height()
	if w == 0 || h == 0 {
		poller.Close()
		return nil, nil, fmt.Errorf("vt framebuffer init failed (vt may not allow mmap on this driver)")
	}
	log.Info("VNC console: FreeBSD has no input backend, serving the console view-only")
	return poller, &vncserver.StubInputInjector{}, nil
}
