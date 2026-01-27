// Package server implements port forwarding for the SSH server.
//
// Security note: Port forwarding runs in the main server process without privilege separation.
// The attack surface is primarily io.Copy through well-tested standard library code, making it
// lower risk than shell execution which uses privilege-separated child processes. We enforce
// user-level port restrictions: non-privileged users cannot bind to ports < 1024.
package server

import (
	"encoding/binary"
	"fmt"
	"net"
	"runtime"
	"strconv"

	"github.com/gliderlabs/ssh"
	log "github.com/sirupsen/logrus"
	cryptossh "golang.org/x/crypto/ssh"

	nbssh "github.com/netbirdio/netbird/client/ssh"
)

const privilegedPortThreshold = 1024

// sessionKey uniquely identifies an SSH session
type sessionKey string

// forwardKey uniquely identifies a port forwarding listener
type forwardKey string

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
		logger := s.getRequestLogger(ctx)
		if !allowLocal {
			logger.Warnf("local port forwarding denied for %s:%d: disabled", dstHost, dstPort)
			return false
		}

		if err := s.checkPortForwardingPrivileges(ctx, "local", dstPort); err != nil {
			logger.Warnf("local port forwarding denied for %s:%d: %v", dstHost, dstPort, err)
			return false
		}

		return true
	}

	server.ReversePortForwardingCallback = func(ctx ssh.Context, bindHost string, bindPort uint32) bool {
		logger := s.getRequestLogger(ctx)
		if !allowRemote {
			logger.Warnf("remote port forwarding denied for %s:%d: disabled", bindHost, bindPort)
			return false
		}

		if err := s.checkPortForwardingPrivileges(ctx, "remote", bindPort); err != nil {
			logger.Warnf("remote port forwarding denied for %s:%d: %v", bindHost, bindPort, err)
			return false
		}

		return true
	}

	log.Debugf("SSH server configured with local_forwarding=%v, remote_forwarding=%v", allowLocal, allowRemote)
}

// checkPortForwardingPrivileges validates privilege requirements for port forwarding operations.
// For remote port forwarding (binding), it enforces that non-privileged users cannot bind to
// ports below 1024, mirroring the restriction they would face if binding directly.
//
// Note: FeatureSupportsUserSwitch is true because we accept requests from any authenticated user,
// though we don't actually switch users - port forwarding runs in the server process. The resolved
// user is used for privileged port access checks.
func (s *Server) checkPortForwardingPrivileges(ctx ssh.Context, forwardType string, port uint32) error {
	if ctx == nil {
		return fmt.Errorf("%s port forwarding denied: no context", forwardType)
	}

	result := s.CheckPrivileges(PrivilegeCheckRequest{
		RequestedUsername:         ctx.User(),
		FeatureSupportsUserSwitch: true,
		FeatureName:               forwardType + " port forwarding",
	})

	if !result.Allowed {
		return result.Error
	}

	if err := s.checkPrivilegedPortAccess(forwardType, port, result); err != nil {
		return err
	}

	return nil
}

// checkPrivilegedPortAccess enforces that non-privileged users cannot bind to privileged ports.
// This applies to remote port forwarding where the server binds a port on behalf of the user.
// On Windows, there is no privileged port restriction, so this check is skipped.
func (s *Server) checkPrivilegedPortAccess(forwardType string, port uint32, result PrivilegeCheckResult) error {
	if runtime.GOOS == "windows" {
		return nil
	}

	isBindOperation := forwardType == "remote" || forwardType == "tcpip-forward"
	if !isBindOperation {
		return nil
	}

	// Port 0 means "pick any available port", which will be >= 1024
	if port == 0 || port >= privilegedPortThreshold {
		return nil
	}

	if result.User != nil && isPrivilegedUsername(result.User.Username) {
		return nil
	}

	username := "unknown"
	if result.User != nil {
		username = result.User.Username
	}
	return fmt.Errorf("user %s cannot bind to privileged port %d (requires root)", username, port)
}

// tcpipForwardHandler handles tcpip-forward requests for remote port forwarding.
func (s *Server) tcpipForwardHandler(ctx ssh.Context, _ *ssh.Server, req *cryptossh.Request) (bool, []byte) {
	logger := s.getRequestLogger(ctx)

	if !s.isRemotePortForwardingAllowed() {
		logger.Warnf("tcpip-forward request denied: remote port forwarding disabled")
		return false, nil
	}

	payload, err := s.parseTcpipForwardRequest(req)
	if err != nil {
		logger.Errorf("tcpip-forward unmarshal error: %v", err)
		return false, nil
	}

	if err := s.checkPortForwardingPrivileges(ctx, "tcpip-forward", payload.Port); err != nil {
		logger.Warnf("tcpip-forward denied: %v", err)
		return false, nil
	}

	sshConn, err := s.getSSHConnection(ctx)
	if err != nil {
		logger.Warnf("tcpip-forward request denied: %v", err)
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

	key := forwardKey(fmt.Sprintf("%s:%d", payload.Host, payload.Port))
	if s.removeRemoteForwardListener(key) {
		forwardAddr := fmt.Sprintf("-R %s:%d", payload.Host, payload.Port)
		s.removeConnectionPortForward(ctx.RemoteAddr(), forwardAddr)
		logger.Infof("remote port forwarding cancelled: %s:%d", payload.Host, payload.Port)
		return true, nil
	}

	logger.Warnf("cancel-tcpip-forward failed: no listener found for %s:%d", payload.Host, payload.Port)
	return false, nil
}

// handleRemoteForwardListener handles incoming connections for remote port forwarding.
func (s *Server) handleRemoteForwardListener(ctx ssh.Context, ln net.Listener, host string, port uint32) {
	logger := s.getRequestLogger(ctx)

	defer func() {
		if err := ln.Close(); err != nil {
			logger.Debugf("remote forward listener close error for %s:%d: %v", host, port, err)
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
				logger.Debugf("remote forward accept error: %v", result.err)
				return
			}
			go s.handleRemoteForwardConnection(ctx, result.conn, host, port)
		case <-ctx.Done():
			logger.Debugf("remote forward listener shutting down for %s:%d", host, port)
			return
		}
	}
}

// getRequestLogger creates a logger with session/conn and jwt_user context
func (s *Server) getRequestLogger(ctx ssh.Context) *log.Entry {
	sessionKey := s.findSessionKeyByContext(ctx)

	s.mu.RLock()
	defer s.mu.RUnlock()

	if state, exists := s.sessions[sessionKey]; exists {
		logger := log.WithField("session", sessionKey)
		if state.jwtUsername != "" {
			logger = logger.WithField("jwt_user", state.jwtUsername)
		}
		return logger
	}

	if ctx.RemoteAddr() != nil {
		if connState, exists := s.connections[connKey(ctx.RemoteAddr().String())]; exists {
			return s.connLogger(connState)
		}
	}

	remoteAddr := "unknown"
	if ctx.RemoteAddr() != nil {
		remoteAddr = ctx.RemoteAddr().String()
	}
	return log.WithField("session", fmt.Sprintf("%s@%s", ctx.User(), remoteAddr))
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

	key := forwardKey(fmt.Sprintf("%s:%d", payload.Host, payload.Port))
	s.storeRemoteForwardListener(key, ln)

	forwardAddr := fmt.Sprintf("-R %s:%d", payload.Host, actualPort)
	s.addConnectionPortForward(ctx.User(), ctx.RemoteAddr(), forwardAddr)
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
	logger := s.getRequestLogger(ctx)

	sshConn, ok := ctx.Value(ssh.ContextKeyConn).(*cryptossh.ServerConn)
	if !ok || sshConn == nil {
		logger.Debugf("remote forward: no SSH connection in context")
		_ = conn.Close()
		return
	}

	remoteAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		logger.Warnf("remote forward: non-TCP connection type: %T", conn.RemoteAddr())
		_ = conn.Close()
		return
	}

	channel, err := s.openForwardChannel(sshConn, host, port, remoteAddr)
	if err != nil {
		logger.Debugf("open forward channel for %s:%d: %v", host, port, err)
		_ = conn.Close()
		return
	}

	nbssh.BidirectionalCopyWithContext(logger, ctx, conn, channel)
}

// openForwardChannel creates an SSH forwarded-tcpip channel
func (s *Server) openForwardChannel(sshConn *cryptossh.ServerConn, host string, port uint32, remoteAddr *net.TCPAddr) (cryptossh.Channel, error) {
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
