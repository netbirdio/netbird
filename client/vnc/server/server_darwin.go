//go:build darwin && !ios

package server

import (
	"net"

	log "github.com/sirupsen/logrus"
)

func (s *Server) platformInit() {
	// no-op on macOS
}

func (s *Server) platformShutdown() {
	// no-op on macOS
}

func (s *Server) platformSessionManager() virtualSessionManager {
	return nil
}

// serviceAcceptLoop runs as a LaunchDaemon and proxies each VNC connection
// to the per-user agent darwinAgentManager spawns via launchctl asuser
// (the only spawn mode that lands a child in the user's Aqua session with
// WindowServer + TCC access).
func (s *Server) serviceAcceptLoop(ln net.Listener) {
	if ln == nil {
		return
	}

	mgr := newDarwinAgentManager(s.ctx)
	defer mgr.stop()

	log.Info("service mode, proxying connections to per-user agent over Unix socket")

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
			}
			s.log.Debugf("accept VNC connection: %v", err)
			continue
		}

		if !s.tryAcquireConnSlot() {
			s.log.Warnf("rejecting VNC connection from %s: %d concurrent connections in flight", conn.RemoteAddr(), maxConcurrentVNCConns)
			_ = conn.Close()
			continue
		}
		enableTCPKeepAlive(conn, s.log)
		conn = newMetricsConn(conn, s.sessionRecorder)
		s.trackConn(conn)
		go func(c net.Conn) {
			defer s.releaseConnSlot()
			defer s.untrackConn(c)
			s.handleServiceConnection(c, mgr)
		}(conn)
	}
}
