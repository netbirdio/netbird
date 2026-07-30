package server

import "context"

// sessionAgent abstracts the per-platform manager that spawns and tracks
// the user-session VNC agent. Resolve returns the agent's Unix-socket
// path, the shared per-spawn token, and the uid the agent was spawned
// under (used to validate peer credentials before the daemon hands the
// token to whoever is on the other end of the socket). Resolve may spawn
// the agent lazily.
type sessionAgent interface {
	Resolve(ctx context.Context) (socketPath, token string, peerUID uint32, err error)
}

// serviceAgent returns the one agent manager this server shares across every
// service-mode accept loop, constructing it on first use.
//
// One per server, not one per listener: the manager owns the agent process for
// the active session, so a second manager spawns a second agent on its own
// socket path, and each accept loop then proxies to a different one. Only one of
// those agents ends up serving, so connections arriving on the other listener
// are refused with the agent socket actively refusing the dial. A dual-stack
// server has two accept loops, since the v6 overlay listener is added after
// Start, which is how that happened.
//
// Returns nil once the server has stopped, and on platforms with no service
// mode.
func (s *Server) serviceAgent() sessionAgent {
	s.serviceAgentMu.Lock()
	defer s.serviceAgentMu.Unlock()

	if s.serviceAgentStopped {
		return nil
	}
	if s.serviceAgentMgr == nil {
		s.serviceAgentMgr, s.serviceAgentStop = s.newServiceAgentManager()
	}
	return s.serviceAgentMgr
}

// stopServiceAgent tears down the shared manager, if one was ever built, and
// latches the server so a still-draining accept loop cannot build another.
// Owned by Stop rather than by an accept loop: the loops share the manager, so
// the first one to exit must not take it away from the others.
func (s *Server) stopServiceAgent() {
	s.serviceAgentMu.Lock()
	stop := s.serviceAgentStop
	s.serviceAgentStop = nil
	s.serviceAgentMgr = nil
	s.serviceAgentStopped = true
	s.serviceAgentMu.Unlock()

	if stop != nil {
		stop()
	}
}
