//go:build !android && !ios && !freebsd && !js

package main

import (
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/client/ui/services"
)

// The one-shot mode this binary runs itself in, elevated, to apply the settings the
// daemon restricts to root/administrator. It is handled before anything GUI, so no
// window, tray or single-instance lock is involved.
//
// Only the wiring is here: what the mode accepts and does lives beside the code
// that asks for it, in services.RunPrivilegedSettings, so the settings it will
// apply are declared once. There is nothing privileged about the mode itself; it
// sends the same request the frontend would have sent, and the daemon authorizes it
// from the identity the kernel reports on the control channel exactly as it does
// for `sudo netbird up`.
func runPrivilegedSettings(args []string) int {
	return services.RunPrivilegedSettings(args, func(addr string) (proto.DaemonServiceClient, error) {
		if addr == "" {
			addr = DaemonAddr()
		}
		return NewConn(addr).Client()
	})
}
