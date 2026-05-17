//go:build (!windows && !darwin && !freebsd && !(linux && !android)) || (darwin && ios)

package server

func (s *Server) platformInit() {
	// no-op on unsupported platforms
}

// serviceAcceptLoop is not supported on non-Windows platforms.
func (s *Server) serviceAcceptLoop() {
	s.log.Warn("service mode not supported on this platform, falling back to direct mode")
	s.acceptLoop()
}

func (s *Server) platformSessionManager() virtualSessionManager {
	return nil
}

func (s *Server) platformShutdown() {
	// no-op on this platform
}
