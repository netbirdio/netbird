//go:build windows

package server

import (
	"context"
	"net"

	"github.com/Microsoft/go-winio"
)

const (
	// agentPipePrefix places agent pipes in the NPFS namespace where only
	// LocalSystem and members of BUILTIN\Administrators may create a pipe, so an
	// unprivileged process cannot pre-create the name the daemon hands the agent.
	agentPipePrefix = `\\.\pipe\ProtectedPrefix\Administrators\netbird-vnc-`

	// agentPipeSDDL lets only LocalSystem open the pipe. The daemon and the
	// agent both run as SYSTEM, and nothing else has a reason to connect.
	agentPipeSDDL = "D:P(A;;GA;;;SY)"
)

// ListenAgentSocket creates the named pipe the vnc-agent serves on. Creation
// fails if a pipe with that name already exists, so the agent never shares a
// name with a process that got there first.
func ListenAgentSocket(path string) (net.Listener, error) {
	return listenAgentPipe(path, agentPipeSDDL)
}

func listenAgentPipe(path, sddl string) (net.Listener, error) {
	return winio.ListenPipe(path, &winio.PipeConfig{SecurityDescriptor: sddl})
}

func dialAgent(ctx context.Context, addr string) (net.Conn, error) {
	return winio.DialPipeContext(ctx, addr)
}
