//go:build darwin && !ios

package server

import (
	"bytes"
	"errors"
	"io"
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

// serviceAcceptLoop runs in a LaunchDaemon and proxies each VNC
// connection to a per-user agent. The agent is spawned lazily on the
// first connection (and respawned after a console-user change) via
// launchctl asuser, which is the only mechanism that lands a child
// inside the user's Aqua session, where WindowServer and TCC grants
// for screen capture work.
func (s *Server) serviceAcceptLoop() {
	mgr := newDarwinAgentManager(s.ctx)
	defer mgr.stop()

	log.Infof("service mode, proxying connections to per-user agent on 127.0.0.1:%d", agentPort)

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
			}
			s.log.Debugf("accept VNC connection: %v", err)
			continue
		}

		enableTCPKeepAlive(conn, s.log)
		conn = newMetricsConn(conn, s.sessionRecorder)
		s.trackConn(conn)
		go func(c net.Conn) {
			defer s.untrackConn(c)
			s.handleServiceConnectionDarwin(c, mgr)
		}(conn)
	}
}

func (s *Server) handleServiceConnectionDarwin(conn net.Conn, mgr *darwinAgentManager) {
	connLog := s.log.WithField("remote", conn.RemoteAddr().String())

	if !s.isAllowedSource(conn.RemoteAddr()) {
		conn.Close()
		return
	}

	var headerBuf bytes.Buffer
	tee := io.TeeReader(conn, &headerBuf)
	teeConn := &darwinPrefixConn{Reader: tee, Conn: conn}

	header, err := readConnectionHeader(teeConn)
	if err != nil {
		connLog.Debugf("read connection header: %v", err)
		conn.Close()
		return
	}

	if !s.disableAuth {
		if s.jwtConfig == nil {
			rejectConnection(conn, codeMessage(RejectCodeAuthConfig, "auth enabled but no identity provider configured"))
			connLog.Warn("auth rejected: no identity provider configured")
			return
		}
		if _, err := s.authenticateJWT(header); err != nil {
			rejectConnection(conn, codeMessage(jwtErrorCode(err), err.Error()))
			connLog.Warnf("auth rejected: %v", err)
			return
		}
	}

	token, err := mgr.ensure(s.ctx)
	if err != nil {
		code := RejectCodeCapturerError
		if errors.Is(err, errNoConsoleUser) {
			code = RejectCodeNoConsoleUser
		}
		rejectConnection(conn, codeMessage(code, err.Error()))
		connLog.Warnf("spawn per-user agent: %v", err)
		return
	}

	replayConn := &darwinPrefixConn{
		Reader: io.MultiReader(&headerBuf, conn),
		Conn:   conn,
	}
	proxyToAgent(replayConn, agentPort, token)
}

// darwinPrefixConn replays the already-consumed connection-header bytes
// in front of the proxy stream, mirroring the Windows prefixConn shape.
type darwinPrefixConn struct {
	io.Reader
	net.Conn
}

func (p *darwinPrefixConn) Read(b []byte) (int, error) { return p.Reader.Read(b) }
