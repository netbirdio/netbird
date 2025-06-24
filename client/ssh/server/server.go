package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/gliderlabs/ssh"
	log "github.com/sirupsen/logrus"
	cryptossh "golang.org/x/crypto/ssh"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
	sshconfig "github.com/netbirdio/netbird/client/ssh/config"
)

// DefaultSSHPort is the default SSH port of the NetBird's embedded SSH server
const DefaultSSHPort = 22

// InternalSSHPort is the port SSH server listens on and is redirected to
const InternalSSHPort = 22022

const (
	errWriteSession = "write session error: %v"
	errExitSession  = "exit session error: %v"

	msgPrivilegedUserDisabled = "privileged user login is disabled"
)

var (
	ErrPrivilegedUserDisabled = errors.New(msgPrivilegedUserDisabled)
	ErrUserNotFound           = errors.New("user not found")
)

// PrivilegedUserError represents an error when privileged user login is disabled
type PrivilegedUserError struct {
	Username string
}

func (e *PrivilegedUserError) Error() string {
	return fmt.Sprintf("%s for user: %s", msgPrivilegedUserDisabled, e.Username)
}

func (e *PrivilegedUserError) Is(target error) bool {
	return target == ErrPrivilegedUserDisabled
}

// UserNotFoundError represents an error when a user cannot be found
type UserNotFoundError struct {
	Username string
	Cause    error
}

func (e *UserNotFoundError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("user %s not found: %v", e.Username, e.Cause)
	}
	return fmt.Sprintf("user %s not found", e.Username)
}

func (e *UserNotFoundError) Is(target error) bool {
	return target == ErrUserNotFound
}

func (e *UserNotFoundError) Unwrap() error {
	return e.Cause
}

// safeLogCommand returns a safe representation of the command for logging
// Only logs the first argument to avoid leaking sensitive information
func safeLogCommand(cmd []string) string {
	if len(cmd) == 0 {
		return "<empty>"
	}
	if len(cmd) == 1 {
		return cmd[0]
	}
	return fmt.Sprintf("%s [%d args]", cmd[0], len(cmd)-1)
}

// sshConnectionState tracks the state of an SSH connection
type sshConnectionState struct {
	hasActivePortForward bool
	username             string
	remoteAddr           string
}

// Server is the SSH server implementation
type Server struct {
	listener       net.Listener
	sshServer      *ssh.Server
	authorizedKeys map[string]ssh.PublicKey
	mu             sync.RWMutex
	hostKeyPEM     []byte
	sessions       map[SessionKey]ssh.Session
	sessionCancels map[ConnectionKey]context.CancelFunc

	allowLocalPortForwarding  bool
	allowRemotePortForwarding bool
	allowRootLogin            bool
	allowSFTP                 bool

	netstackNet *netstack.Net

	wgAddress wgaddr.Address
	ifIdx     int

	remoteForwardListeners map[ForwardKey]net.Listener
	sshConnections         map[*cryptossh.ServerConn]*sshConnectionState
}

// New creates an SSH server instance with the provided host key
func New(hostKeyPEM []byte) *Server {
	return &Server{
		mu:                     sync.RWMutex{},
		hostKeyPEM:             hostKeyPEM,
		authorizedKeys:         make(map[string]ssh.PublicKey),
		sessions:               make(map[SessionKey]ssh.Session),
		remoteForwardListeners: make(map[ForwardKey]net.Listener),
		sshConnections:         make(map[*cryptossh.ServerConn]*sshConnectionState),
	}
}

// Start runs the SSH server, automatically detecting netstack vs standard networking
// Does all setup synchronously, then starts serving in a goroutine and returns immediately
func (s *Server) Start(ctx context.Context, addr netip.AddrPort) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sshServer != nil {
		return errors.New("SSH server is already running")
	}

	ln, addrDesc, err := s.createListener(ctx, addr)
	if err != nil {
		return fmt.Errorf("create listener: %w", err)
	}

	if err := s.setupSocketFilter(ln); err != nil {
		s.closeListener(ln)
		return fmt.Errorf("setup socket filter: %w", err)
	}

	sshServer, err := s.createSSHServer(ln)
	if err != nil {
		s.cleanupOnError(ln)
		return fmt.Errorf("create SSH server: %w", err)
	}

	s.initializeServerState(ln, sshServer)
	log.Infof("SSH server started on %s", addrDesc)

	go s.serve(ln, sshServer)
	return nil
}

// createListener creates a network listener based on netstack vs standard networking
func (s *Server) createListener(ctx context.Context, addr netip.AddrPort) (net.Listener, string, error) {
	if s.netstackNet != nil {
		ln, err := s.netstackNet.ListenTCPAddrPort(addr)
		if err != nil {
			return nil, "", fmt.Errorf("listen on netstack: %w", err)
		}
		return ln, fmt.Sprintf("netstack %s", addr), nil
	}

	tcpAddr := net.TCPAddrFromAddrPort(addr)
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", tcpAddr.String())
	if err != nil {
		return nil, "", fmt.Errorf("listen: %w", err)
	}
	return ln, addr.String(), nil
}

// setupSocketFilter attaches socket filter if needed
func (s *Server) setupSocketFilter(ln net.Listener) error {
	if s.ifIdx == 0 || ln == nil || s.netstackNet != nil {
		return nil
	}
	return attachSocketFilter(ln, s.ifIdx)
}

// closeListener safely closes a listener
func (s *Server) closeListener(ln net.Listener) {
	if err := ln.Close(); err != nil {
		log.Debugf("listener close error: %v", err)
	}
}

// cleanupOnError cleans up resources when SSH server creation fails
func (s *Server) cleanupOnError(ln net.Listener) {
	if s.ifIdx == 0 || ln == nil {
		return
	}

	if err := detachSocketFilter(ln); err != nil {
		log.Errorf("failed to detach socket filter: %v", err)
	}
	s.closeListener(ln)
}

// initializeServerState sets up server state after successful setup
func (s *Server) initializeServerState(ln net.Listener, sshServer *ssh.Server) {
	s.listener = ln
	s.sshServer = sshServer
}

// Stop closes the SSH server
func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sshServer == nil {
		return nil
	}

	if s.ifIdx > 0 && s.listener != nil {
		if err := detachSocketFilter(s.listener); err != nil {
			// without detaching the filter, the listener will block on shutdown
			return fmt.Errorf("detach socket filter: %w", err)
		}
	}

	if err := s.sshServer.Close(); err != nil && !isShutdownError(err) {
		return fmt.Errorf("shutdown SSH server: %w", err)
	}

	s.sshServer = nil
	s.listener = nil

	return nil
}

// RemoveAuthorizedKey removes the SSH key for a peer
func (s *Server) RemoveAuthorizedKey(peer string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.authorizedKeys, peer)
}

// AddAuthorizedKey adds an SSH key for a peer
func (s *Server) AddAuthorizedKey(peer, newKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	parsedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(newKey))
	if err != nil {
		return fmt.Errorf("parse key: %w", err)
	}

	s.authorizedKeys[peer] = parsedKey
	return nil
}

// SetNetstackNet sets the netstack network for userspace networking
func (s *Server) SetNetstackNet(net *netstack.Net) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.netstackNet = net
}

// SetNetworkValidation configures network-based connection filtering
func (s *Server) SetNetworkValidation(addr wgaddr.Address) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.wgAddress = addr
}

// SetSocketFilter configures eBPF socket filtering for the SSH server
func (s *Server) SetSocketFilter(ifIdx int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ifIdx = ifIdx
}

// SetupSSHClientConfig configures SSH client settings
func (s *Server) SetupSSHClientConfig() error {
	return s.SetupSSHClientConfigWithPeers(nil)
}

// SetupSSHClientConfigWithPeers configures SSH client settings for peer hostnames
func (s *Server) SetupSSHClientConfigWithPeers(peerKeys []sshconfig.PeerHostKey) error {
	configMgr := sshconfig.NewManager()
	if err := configMgr.SetupSSHClientConfigWithPeers(nil, peerKeys); err != nil {
		return fmt.Errorf("setup SSH client config: %w", err)
	}

	peerCount := len(peerKeys)
	if peerCount > 0 {
		log.Debugf("SSH client config setup completed for %d peer hostnames", peerCount)
	} else {
		log.Debugf("SSH client config setup completed with no peers")
	}
	return nil
}

func (s *Server) publicKeyHandler(ctx ssh.Context, key ssh.PublicKey) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, allowed := range s.authorizedKeys {
		if ssh.KeysEqual(allowed, key) {
			if ctx != nil {
				log.Debugf("SSH key authentication successful for user %s from %s", ctx.User(), ctx.RemoteAddr())
			}
			return true
		}
	}

	if ctx != nil {
		log.Warnf("SSH key authentication failed for user %s from %s: key not authorized (type: %s, fingerprint: %s)",
			ctx.User(), ctx.RemoteAddr(), key.Type(), cryptossh.FingerprintSHA256(key))
	}
	return false
}

// markConnectionActivePortForward marks an SSH connection as having an active port forward
func (s *Server) markConnectionActivePortForward(sshConn *cryptossh.ServerConn, username, remoteAddr string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if state, exists := s.sshConnections[sshConn]; exists {
		state.hasActivePortForward = true
	} else {
		s.sshConnections[sshConn] = &sshConnectionState{
			hasActivePortForward: true,
			username:             username,
			remoteAddr:           remoteAddr,
		}
	}
}

// connectionCloseHandler cleans up connection state when SSH connections fail/close
func (s *Server) connectionCloseHandler(conn net.Conn, err error) {
	// We can't extract the SSH connection from net.Conn directly
	// Connection cleanup will happen during session cleanup or via timeout
	log.Debugf("SSH connection failed for %s: %v", conn.RemoteAddr(), err)
}

// findSessionKeyByContext finds the session key by matching SSH connection context
func (s *Server) findSessionKeyByContext(ctx ssh.Context) SessionKey {
	if ctx == nil {
		return "unknown"
	}

	// Try to match by SSH connection
	sshConn := ctx.Value(ssh.ContextKeyConn)
	if sshConn == nil {
		return "unknown"
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	// Look through sessions to find one with matching connection
	for sessionKey, session := range s.sessions {
		if session.Context().Value(ssh.ContextKeyConn) == sshConn {
			return sessionKey
		}
	}

	// If no session found, this might be during early connection setup
	// Return a temporary key that we'll fix up later
	if ctx.User() != "" && ctx.RemoteAddr() != nil {
		tempKey := SessionKey(fmt.Sprintf("%s@%s", ctx.User(), ctx.RemoteAddr().String()))
		log.Debugf("using temporary session key for port forward tracking: %s", tempKey)
		return tempKey
	}

	return "unknown"
}

// cleanupConnectionPortForward removes port forward state from a connection
func (s *Server) cleanupConnectionPortForward(sshConn *cryptossh.ServerConn) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if state, exists := s.sshConnections[sshConn]; exists {
		state.hasActivePortForward = false
	}
}

// connectionValidator validates incoming connections based on source IP
func (s *Server) connectionValidator(_ ssh.Context, conn net.Conn) net.Conn {
	s.mu.RLock()
	netbirdNetwork := s.wgAddress.Network
	localIP := s.wgAddress.IP
	s.mu.RUnlock()

	if !netbirdNetwork.IsValid() || !localIP.IsValid() {
		return conn
	}

	remoteAddr := conn.RemoteAddr()
	tcpAddr, ok := remoteAddr.(*net.TCPAddr)
	if !ok {
		log.Debugf("SSH connection from non-TCP address %s allowed", remoteAddr)
		return conn
	}

	remoteIP, ok := netip.AddrFromSlice(tcpAddr.IP)
	if !ok {
		log.Warnf("SSH connection rejected: invalid remote IP %s", tcpAddr.IP)
		return nil
	}

	// Block connections from our own IP (prevent local apps from connecting to ourselves)
	if remoteIP == localIP {
		log.Warnf("SSH connection rejected from own IP %s", remoteIP)
		return nil
	}

	if !netbirdNetwork.Contains(remoteIP) {
		log.Warnf("SSH connection rejected from non-NetBird IP %s (allowed range: %s)", remoteIP, netbirdNetwork)
		return nil
	}

	log.Debugf("SSH connection from %s allowed", remoteIP)
	return conn
}

// serve runs the SSH server in a goroutine
func (s *Server) serve(ln net.Listener, sshServer *ssh.Server) {
	if ln == nil {
		log.Debug("SSH server serve called with nil listener")
		return
	}

	err := sshServer.Serve(ln)
	if err == nil {
		return
	}

	if isShutdownError(err) {
		return
	}

	log.Errorf("SSH server error: %v", err)
}

// isShutdownError checks if the error is expected during normal shutdown
func isShutdownError(err error) bool {
	if errors.Is(err, net.ErrClosed) {
		return true
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "accept" {
		return true
	}

	return false
}

// createSSHServer creates and configures the SSH server
func (s *Server) createSSHServer(listener net.Listener) (*ssh.Server, error) {
	if err := enableUserSwitching(); err != nil {
		log.Warnf("failed to enable user switching: %v", err)
	}

	server := &ssh.Server{
		Addr:    listener.Addr().String(),
		Handler: s.sessionHandler,
		SubsystemHandlers: map[string]ssh.SubsystemHandler{
			"sftp": s.sftpSubsystemHandler,
		},
		HostSigners: []ssh.Signer{},
		ChannelHandlers: map[string]ssh.ChannelHandler{
			"session":      ssh.DefaultSessionHandler,
			"direct-tcpip": s.directTCPIPHandler,
		},
		RequestHandlers: map[string]ssh.RequestHandler{
			"tcpip-forward":        s.tcpipForwardHandler,
			"cancel-tcpip-forward": s.cancelTcpipForwardHandler,
		},
		ConnCallback:             s.connectionValidator,
		ConnectionFailedCallback: s.connectionCloseHandler,
	}

	hostKeyPEM := ssh.HostKeyPEM(s.hostKeyPEM)
	if err := server.SetOption(hostKeyPEM); err != nil {
		return nil, fmt.Errorf("set host key: %w", err)
	}

	s.configurePortForwarding(server)
	return server, nil
}

// storeRemoteForwardListener stores a remote forward listener for cleanup
func (s *Server) storeRemoteForwardListener(key ForwardKey, ln net.Listener) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.remoteForwardListeners[key] = ln
}

// removeRemoteForwardListener removes and closes a remote forward listener
func (s *Server) removeRemoteForwardListener(key ForwardKey) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	ln, exists := s.remoteForwardListeners[key]
	if !exists {
		return false
	}

	delete(s.remoteForwardListeners, key)
	if err := ln.Close(); err != nil {
		log.Debugf("remote forward listener close error: %v", err)
	}

	return true
}

// directTCPIPHandler handles direct-tcpip channel requests for local port forwarding with privilege validation
func (s *Server) directTCPIPHandler(srv *ssh.Server, conn *cryptossh.ServerConn, newChan cryptossh.NewChannel, ctx ssh.Context) {
	var payload struct {
		Host           string
		Port           uint32
		OriginatorAddr string
		OriginatorPort uint32
	}

	if err := cryptossh.Unmarshal(newChan.ExtraData(), &payload); err != nil {
		if err := newChan.Reject(cryptossh.ConnectionFailed, "parse payload"); err != nil {
			log.Debugf("channel reject error: %v", err)
		}
		return
	}

	s.mu.RLock()
	allowLocal := s.allowLocalPortForwarding
	s.mu.RUnlock()

	if !allowLocal {
		log.Debugf("direct-tcpip rejected: local port forwarding disabled")
		_ = newChan.Reject(cryptossh.Prohibited, "local port forwarding disabled")
		return
	}

	// Check privilege requirements for the destination port
	if err := s.checkPortForwardingPrivileges(ctx, "local", payload.Port); err != nil {
		log.Infof("direct-tcpip denied: %v", err)
		_ = newChan.Reject(cryptossh.Prohibited, "insufficient privileges")
		return
	}

	log.Debugf("direct-tcpip request: %s:%d", payload.Host, payload.Port)

	ssh.DirectTCPIPHandler(srv, conn, newChan, ctx)
}
