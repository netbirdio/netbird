//go:build windows

package cmd

import "net"

// secureDaemonListener is a no-op on Windows: the named-pipe SDDL gates who may
// connect (Layer 1), and the pipe client token supplies per-RPC identity.
func secureDaemonListener(l *socketListener) (net.Listener, error) {
	return l.Listener, nil
}
