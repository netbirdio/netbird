//go:build (linux && !android) || freebsd

package server

func (s *Server) platformInit() {
	// no-op on X11
}

// serviceAcceptLoop is not supported on Linux.
func (s *Server) serviceAcceptLoop() {
	s.log.Warn("service mode not supported on Linux, falling back to direct mode")
	s.acceptLoop()
}

func (s *Server) platformSessionManager() virtualSessionManager {
	return newSessionManager(s.log)
}

func (s *Server) platformShutdown() {
	// no-op on this platform
}
