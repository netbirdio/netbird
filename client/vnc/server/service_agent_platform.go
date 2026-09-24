//go:build darwin || windows

package server

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
