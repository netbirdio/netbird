//go:build windows

package server

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/windows"
)

// validateAgentPeer checks that the pipe the daemon connected to is served by
// the agent process it spawned. The pipe name sits in the protected namespace,
// so only SYSTEM or an administrator could have created it; the PID check pins
// it to the spawned agent. The daemon holds the agent's process handle for the
// agent's lifetime, so the PID cannot be recycled underneath the check. Fails
// closed when no PID is known or the query fails.
func validateAgentPeer(conn net.Conn, expectedPID uint32) error {
	if expectedPID == 0 {
		return errors.New("no agent PID to verify the pipe server against")
	}
	// go-winio's pipe connection embeds *win32File, which exposes Fd().
	fdConn, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return fmt.Errorf("agent connection %T exposes no pipe handle", conn)
	}
	var pid uint32
	if err := windows.GetNamedPipeServerProcessId(windows.Handle(fdConn.Fd()), &pid); err != nil {
		return fmt.Errorf("query pipe server PID: %w", err)
	}
	if pid != expectedPID {
		return fmt.Errorf("pipe served by PID %d, expected agent PID %d", pid, expectedPID)
	}
	return nil
}
