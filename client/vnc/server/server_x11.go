//go:build (linux && !android) || freebsd

package server

import "net"

func (s *Server) platformInit() {
	// no-op on X11
}

// serviceAcceptLoop is not supported on Linux.
func (s *Server) serviceAcceptLoop(ln net.Listener) {
	s.log.Warn("service mode not supported on Linux, falling back to direct mode")
	s.acceptLoop(ln)
}

func (s *Server) platformSessionManager() virtualSessionManager {
	return newSessionManager(s.log)
}

func (s *Server) platformShutdown() {
	// no-op on this platform
}

// newServiceAgentManager has no service mode to manage on this platform;
// serviceAcceptLoop falls back to direct mode and never asks for it.
func (s *Server) newServiceAgentManager() (sessionAgent, func()) {
	return nil, nil
}
