//go:build windows

package server

import (
	"net"
)

// validateAgentPeer is a best-effort no-op on Windows: AF_UNIX sockets on
// Windows do not expose SO_PEERCRED equivalents, and both the daemon and
// the spawned agent run as SYSTEM in distinct sessions. The remaining
// trust comes from the location of the socket file (under
// C:\Windows\Temp, writable only by SYSTEM/Administrators) and from the
// per-spawn auth token preamble that follows this call. Documented as a
// known gap; a future hardening pass could interrogate the connected
// pipe's PID via process-token APIs.
func validateAgentPeer(_ net.Conn, _ uint32) error {
	return nil
}
