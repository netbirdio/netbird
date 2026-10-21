package server

import "context"

// sessionAgent abstracts the per-platform manager that spawns and tracks
// the user-session VNC agent. Resolve returns the agent's socket path (a
// named pipe on Windows), the shared per-spawn token, and the peer identity
// the daemon expects on the other end: the uid the agent runs under on
// darwin, the agent's PID on Windows. Resolve may spawn the agent lazily.
// Release reports that one proxied connection is done with the agent, so a
// platform that recycles the agent per connection can tear it down once the last
// one is gone. Every successful Resolve owes exactly one Release.
type sessionAgent interface {
	Resolve(ctx context.Context) (socketPath, token string, peerID uint32, err error)
	Release()
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
