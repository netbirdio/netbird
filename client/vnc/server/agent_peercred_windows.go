//go:build windows

package server

import (
	"net"
)

// validateAgentPeer is a documented no-op on Windows. AF_UNIX on Windows
// exposes no SO_PEERCRED equivalent and no supported API to recover the
// peer process from an accepted AF_UNIX connection, so the daemon cannot
// match the connected peer against the agent PID it spawned the way the
// darwin path does via LOCAL_PEERCRED. The Windows trust model therefore
// rests on three other measures, none of which assume the socket path is
// secret:
//
//   - the socket lives in a dedicated directory (agentSocketDir) created
//     with a DACL granting only SYSTEM and Administrators, so an
//     unprivileged local user cannot create or squat a socket there;
//   - each spawn uses a cryptographically random socket name, so the path
//     is unguessable before the agent binds it;
//   - the daemon publishes the path only after confirming the spawned
//     agent is listening (see waitForAgentListening), and gates every
//     connection on the per-spawn auth-token preamble that follows this
//     call.
//
// If a future Windows release exposes peer-PID retrieval for AF_UNIX,
// this function should verify the peer against the spawned agent PID.
func validateAgentPeer(_ net.Conn, _ uint32) error {
	return nil
}
