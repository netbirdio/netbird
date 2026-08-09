//go:build freebsd

package internal

import (
	"fmt"

	log "github.com/sirupsen/logrus"

	vncserver "github.com/netbirdio/netbird/client/vnc/server"
)

// newConsoleVNC builds the FreeBSD console fallback: vt(4) framebuffer
// for capture, /dev/uinput for input. The uinput device requires the
// `uinput` kernel module (`kldload uinput`); without it, input init
// fails and we drop to a stub injector so the user still gets a
// view-only screen mirror.
func newConsoleVNC() (vncserver.ScreenCapturer, vncserver.InputInjector, error) {
	poller := vncserver.NewFBPoller("")
	w, h := poller.Width(), poller.Height()
	if w == 0 || h == 0 {
		poller.Close()
		return nil, nil, fmt.Errorf("vt framebuffer init failed (vt may not allow mmap on this driver)")
	}
	if inj, err := vncserver.NewUInputInjector(w, h); err == nil {
		return poller, inj, nil
	} else {
		log.Infof("VNC console: uinput unavailable (%v); view-only mode. Run `kldload uinput` to enable input.", err)
		return poller, &vncserver.StubInputInjector{}, nil
	}
}
