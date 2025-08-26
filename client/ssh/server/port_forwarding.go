package server

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/gliderlabs/ssh"
	log "github.com/sirupsen/logrus"
	cryptossh "golang.org/x/crypto/ssh"
)

// SessionKey uniquely identifies an SSH session
type SessionKey string

// ConnectionKey uniquely identifies a port forwarding connection within a session
type ConnectionKey string

// ForwardKey uniquely identifies a port forwarding listener
type ForwardKey string

// tcpipForwardMsg represents the structure for tcpip-forward SSH requests
type tcpipForwardMsg struct {
	Host string
	Port uint32
}

// SetAllowLocalPortForwarding configures local port forwarding
func (s *Server) SetAllowLocalPortForwarding(allow bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.allowLocalPortForwarding = allow
}

// SetAllowRemotePortForwarding configures remote port forwarding
func (s *Server) SetAllowRemotePortForwarding(allow bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.allowRemotePortForwarding = allow
}

// configurePortForwarding sets up port forwarding callbacks
func (s *Server) configurePortForwarding(server *ssh.Server) {
	allowLocal := s.allowLocalPortForwarding
	allowRemote := s.allowRemotePortForwarding

	server.LocalPortForwardingCallback = func(ctx ssh.Context, dstHost string, dstPort uint32) bool {
		if !allowLocal {
			log.Debugf("local port forwarding denied: %s:%d (disabled by configuration)", dstHost, dstPort)
			return false
		}

		if err := s.checkPortForwardingPrivileges(ctx, "local", dstPort); err != nil {
			log.Infof("local port forwarding denied: %v", err)
			return false
		}

		log.Debugf("local port forwarding allowed: %s:%d", dstHost, dstPort)
		return true
	}

	server.ReversePortForwardingCallback = func(ctx ssh.Context, bindHost string, bindPort uint32) bool {
		if !allowRemote {
			log.Debugf("remote port forwarding denied: %s:%d (disabled by configuration)", bindHost, bindPort)
			return false
		}

		if err := s.checkPortForwardingPrivileges(ctx, "remote", bindPort); err != nil {
			log.Infof("remote port forwarding denied: %v", err)
			return false
		}

		log.Debugf("remote port forwarding allowed: %s:%d", bindHost, bindPort)
		return true
	}

	log.Debugf("SSH server configured with local_forwarding=%v, remote_forwarding=%v", allowLocal, allowRemote)
}

// checkPortForwardingPrivileges validates privilege requirements for port forwarding operations.
// Returns nil if allowed, error if denied.
func (s *Server) checkPortForwardingPrivileges(ctx ssh.Context, forwardType string, port uint32) error {
	if ctx == nil {
		return fmt.Errorf("%s port forwarding denied: no context", forwardType)
	}

	username := ctx.User()
	remoteAddr := "unknown"
	if ctx.RemoteAddr() != nil {
		remoteAddr = ctx.RemoteAddr().String()
	}

	logger := log.WithFields(log.Fields{"user": username, "remote": remoteAddr, "port": port})

	result := s.CheckPrivileges(PrivilegeCheckRequest{
		RequestedUsername:         username,
		FeatureSupportsUserSwitch: false,
		FeatureName:               forwardType + " port forwarding",
	})

	if !result.Allowed {
		return result.Error
	}

	logger.Debugf("%s port forwarding allowed: user %s validated (port %d)",
		forwardType, result.User.Username, port)

	return nil
}

// tcpipForwardHandler handles tcpip-forward requests for remote port forwarding.
func (s *Server) tcpipForwardHandler(ctx ssh.Context, _ *ssh.Server, req *cryptossh.Request) (bool, []byte) {
	logger := s.getRequestLogger(ctx)

	if !s.isRemotePortForwardingAllowed() {
		logger.Debugf("tcpip-forward request denied: remote port forwarding disabled")
		return false, nil
	}

	payload, err := s.parseTcpipForwardRequest(req)
	if err != nil {
		logger.Errorf("tcpip-forward unmarshal error: %v", err)
		return false, nil
	}

	if err := s.checkPortForwardingPrivileges(ctx, "tcpip-forward", payload.Port); err != nil {
		logger.Infof("tcpip-forward denied: %v", err)
		return false, nil
	}

	logger.Debugf("tcpip-forward request: %s:%d", payload.Host, payload.Port)

	sshConn, err := s.getSSHConnection(ctx)
	if err != nil {
		logger.Debugf("tcpip-forward request denied: %v", err)
		return false, nil
	}

	return s.setupDirectForward(ctx, logger, sshConn, payload)
}

// cancelTcpipForwardHandler handles cancel-tcpip-forward requests.
func (s *Server) cancelTcpipForwardHandler(ctx ssh.Context, _ *ssh.Server, req *cryptossh.Request) (bool, []byte) {
	logger := s.getRequestLogger(ctx)

	var payload tcpipForwardMsg
	if err := cryptossh.Unmarshal(req.Payload, &payload); err != nil {
		logger.Errorf("cancel-tcpip-forward unmarshal error: %v", err)
		return false, nil
	}

	key := ForwardKey(fmt.Sprintf("%s:%d", payload.Host, payload.Port))
	if s.removeRemoteForwardListener(key) {
		logger.Infof("cancelled remote port forwarding: %s:%d", payload.Host, payload.Port)
		return true, nil
	}

	logger.Warnf("cancel-tcpip-forward failed: no listener found for %s:%d", payload.Host, payload.Port)
	return false, nil
}

// handleRemoteForwardListener handles incoming connections for remote port forwarding.
func (s *Server) handleRemoteForwardListener(ctx ssh.Context, ln net.Listener, host string, port uint32) {
	log.Debugf("starting remote forward listener handler for %s:%d", host, port)

	defer func() {
		log.Debugf("cleaning up remote forward listener for %s:%d", host, port)
		if err := ln.Close(); err != nil {
			log.Debugf("remote forward listener close error: %v", err)
		} else {
			log.Debugf("remote forward listener closed successfully for %s:%d", host, port)
		}
	}()

	acceptChan := make(chan acceptResult, 1)

	go func() {
		for {
			conn, err := ln.Accept()
			select {
			case acceptChan <- acceptResult{conn: conn, err: err}:
				if err != nil {
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	for {
		select {
		case result := <-acceptChan:
			if result.err != nil {
				log.Debugf("remote forward accept error: %v", result.err)
				return
			}
			go s.handleRemoteForwardConnection(ctx, result.conn, host, port)
		case <-ctx.Done():
			log.Debugf("remote forward listener shutting down due to context cancellation for %s:%d", host, port)
			return
		}
	}
}

// getRequestLogger creates a logger with user and remote address context
func (s *Server) getRequestLogger(ctx ssh.Context) *log.Entry {
	remoteAddr := "unknown"
	username := "unknown"
	if ctx != nil {
		if ctx.RemoteAddr() != nil {
			remoteAddr = ctx.RemoteAddr().String()
		}
		username = ctx.User()
	}
	return log.WithFields(log.Fields{"user": username, "remote": remoteAddr})
}

// isRemotePortForwardingAllowed checks if remote port forwarding is enabled
func (s *Server) isRemotePortForwardingAllowed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.allowRemotePortForwarding
}

// parseTcpipForwardRequest parses the SSH request payload
func (s *Server) parseTcpipForwardRequest(req *cryptossh.Request) (*tcpipForwardMsg, error) {
	var payload tcpipForwardMsg
	err := cryptossh.Unmarshal(req.Payload, &payload)
	return &payload, err
}

// getSSHConnection extracts SSH connection from context
func (s *Server) getSSHConnection(ctx ssh.Context) (*cryptossh.ServerConn, error) {
	if ctx == nil {
		return nil, fmt.Errorf("no context")
	}
	sshConnValue := ctx.Value(ssh.ContextKeyConn)
	if sshConnValue == nil {
		return nil, fmt.Errorf("no SSH connection in context")
	}
	sshConn, ok := sshConnValue.(*cryptossh.ServerConn)
	if !ok || sshConn == nil {
		return nil, fmt.Errorf("invalid SSH connection in context")
	}
	return sshConn, nil
}

// setupDirectForward sets up a direct port forward
func (s *Server) setupDirectForward(ctx ssh.Context, logger *log.Entry, sshConn *cryptossh.ServerConn, payload *tcpipForwardMsg) (bool, []byte) {
	bindAddr := net.JoinHostPort(payload.Host, strconv.FormatUint(uint64(payload.Port), 10))

	ln, err := net.Listen("tcp", bindAddr)
	if err != nil {
		logger.Errorf("tcpip-forward listen failed on %s: %v", bindAddr, err)
		return false, nil
	}

	actualPort := payload.Port
	if payload.Port == 0 {
		tcpAddr := ln.Addr().(*net.TCPAddr)
		actualPort = uint32(tcpAddr.Port)
		logger.Debugf("tcpip-forward allocated port %d for %s", actualPort, payload.Host)
	}

	key := ForwardKey(fmt.Sprintf("%s:%d", payload.Host, payload.Port))
	s.storeRemoteForwardListener(key, ln)

	s.markConnectionActivePortForward(sshConn, ctx.User(), ctx.RemoteAddr().String())
	go s.handleRemoteForwardListener(ctx, ln, payload.Host, actualPort)

	response := make([]byte, 4)
	binary.BigEndian.PutUint32(response, actualPort)

	logger.Infof("remote port forwarding established: %s:%d", payload.Host, actualPort)
	return true, response
}

// acceptResult holds the result of a listener Accept() call
type acceptResult struct {
	conn net.Conn
	err  error
}

// handleRemoteForwardConnection handles a single remote port forwarding connection
func (s *Server) handleRemoteForwardConnection(ctx ssh.Context, conn net.Conn, host string, port uint32) {
	sessionKey := s.findSessionKeyByContext(ctx)
	connID := fmt.Sprintf("pf-%s->%s:%d", conn.RemoteAddr(), host, port)
	logger := log.WithFields(log.Fields{
		"session": sessionKey,
		"conn":    connID,
	})

	defer func() {
		if err := conn.Close(); err != nil {
			logger.Debugf("connection close error: %v", err)
		}
	}()

	sshConn := ctx.Value(ssh.ContextKeyConn).(*cryptossh.ServerConn)
	if sshConn == nil {
		logger.Debugf("remote forward: no SSH connection in context")
		return
	}

	remoteAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		logger.Warnf("remote forward: non-TCP connection type: %T", conn.RemoteAddr())
		return
	}

	channel, err := s.openForwardChannel(sshConn, host, port, remoteAddr, logger)
	if err != nil {
		logger.Debugf("open forward channel: %v", err)
		return
	}

	s.proxyForwardConnection(ctx, logger, conn, channel)
}

// openForwardChannel creates an SSH forwarded-tcpip channel
func (s *Server) openForwardChannel(sshConn *cryptossh.ServerConn, host string, port uint32, remoteAddr *net.TCPAddr, logger *log.Entry) (cryptossh.Channel, error) {
	logger.Tracef("opening forwarded-tcpip channel for %s:%d", host, port)

	payload := struct {
		ConnectedAddress  string
		ConnectedPort     uint32
		OriginatorAddress string
		OriginatorPort    uint32
	}{
		ConnectedAddress:  host,
		ConnectedPort:     port,
		OriginatorAddress: remoteAddr.IP.String(),
		OriginatorPort:    uint32(remoteAddr.Port),
	}

	channel, reqs, err := sshConn.OpenChannel("forwarded-tcpip", cryptossh.Marshal(&payload))
	if err != nil {
		return nil, fmt.Errorf("open SSH channel: %w", err)
	}

	go cryptossh.DiscardRequests(reqs)
	return channel, nil
}

// proxyForwardConnection handles bidirectional data transfer between connection and SSH channel
func (s *Server) proxyForwardConnection(ctx ssh.Context, logger *log.Entry, conn net.Conn, channel cryptossh.Channel) {
	done := make(chan struct{}, 2)

	go func() {
		if _, err := io.Copy(channel, conn); err != nil {
			logger.Debugf("copy error (conn->channel): %v", err)
		}
		done <- struct{}{}
	}()

	go func() {
		if _, err := io.Copy(conn, channel); err != nil {
			logger.Debugf("copy error (channel->conn): %v", err)
		}
		done <- struct{}{}
	}()

	select {
	case <-ctx.Done():
		logger.Debugf("session ended, closing connections")
	case <-done:
		// First copy finished, wait for second copy or context cancellation
		select {
		case <-ctx.Done():
			logger.Debugf("session ended, closing connections")
		case <-done:
		}
	}

	if err := channel.Close(); err != nil {
		logger.Debugf("channel close error: %v", err)
	}
	if err := conn.Close(); err != nil {
		logger.Debugf("connection close error: %v", err)
	}
}
