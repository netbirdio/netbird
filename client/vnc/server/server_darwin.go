//go:build darwin && !ios

package server

func (s *Server) platformInit() {
	// no-op on macOS
}

// serviceAcceptLoop is not supported on macOS.
func (s *Server) serviceAcceptLoop() {
	s.log.Warn("service mode not supported on macOS, falling back to direct mode")
	s.acceptLoop()
}

func (s *Server) platformSessionManager() virtualSessionManager {
	return nil
}

func (s *Server) platformShutdown() {
	// no-op on this platform
}
