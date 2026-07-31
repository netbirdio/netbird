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
