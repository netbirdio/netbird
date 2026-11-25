//go:build darwin && !ios

package server

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// validateAgentPeer enforces that the peer behind the just-connected Unix
// socket is the agent we expect it to be: a process running under
// expectedUID, with the right effective uid stamped by the kernel on the
// socket. Refuses (with a non-nil error) if anything else is listening on
// the path (an unrelated local process that won the listen race or
// squatted the path before us). Defends against the daemon shipping its
// per-spawn auth token to a process that isn't the spawned agent.
func validateAgentPeer(conn net.Conn, expectedUID uint32) error {
	uconn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("peer cred: expected *net.UnixConn, got %T", conn)
	}
	raw, err := uconn.SyscallConn()
	if err != nil {
		return fmt.Errorf("peer cred: syscall conn: %w", err)
	}
	var cred *unix.Xucred
	var inner error
	ctlErr := raw.Control(func(fd uintptr) {
		cred, inner = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	})
	if ctlErr != nil {
		return fmt.Errorf("peer cred: control: %w", ctlErr)
	}
	if inner != nil {
		return fmt.Errorf("peer cred: getsockopt LOCAL_PEERCRED: %w", inner)
	}
	if cred == nil {
		return fmt.Errorf("peer cred: nil xucred")
	}
	if cred.Uid != expectedUID {
		return fmt.Errorf("peer cred: agent uid %d does not match expected %d", cred.Uid, expectedUID)
	}
	return nil
}
