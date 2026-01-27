package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gliderlabs/ssh"
	gojwt "github.com/golang-jwt/jwt/v5"
	log "github.com/sirupsen/logrus"
	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/exp/maps"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
	sshauth "github.com/netbirdio/netbird/client/ssh/auth"
	"github.com/netbirdio/netbird/client/ssh/detection"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/auth/jwt"
	"github.com/netbirdio/netbird/version"
)

// DefaultSSHPort is the default SSH port of the NetBird's embedded SSH server
const DefaultSSHPort = 22

// InternalSSHPort is the port SSH server listens on and is redirected to
const InternalSSHPort = 22022

const (
	errWriteSession = "write session error: %v"
	errExitSession  = "exit session error: %v"

	msgPrivilegedUserDisabled = "privileged user login is disabled"

	cmdInteractiveShell = "<interactive shell>"
	cmdPortForwarding   = "<port forwarding>"
	cmdSFTP             = "<sftp>"
	cmdNonInteractive   = "<idle>"

	// DefaultJWTMaxTokenAge is the default maximum age for JWT tokens accepted by the SSH server
	DefaultJWTMaxTokenAge = 5 * 60
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

// logSessionExitError logs session exit errors, ignoring EOF (normal close) errors
func logSessionExitError(logger *log.Entry, err error) {
	if err != nil && !errors.Is(err, io.EOF) {
		logger.Warnf(errExitSession, err)
	}
}

// safeLogCommand returns a safe representation of the command for logging.
func safeLogCommand(cmd []string) string {
	if len(cmd) == 0 {
		return cmdInteractiveShell
	}
	if len(cmd) == 1 {
		return cmd[0]
	}
	return fmt.Sprintf("%s [%d args]", cmd[0], len(cmd)-1)
}

// connState tracks the state of an SSH connection for port forwarding and status display.
type connState struct {
	username     string
	remoteAddr   net.Addr
	portForwards []string
	jwtUsername  string
}

// authKey uniquely identifies an authentication attempt by username and remote address.
// Used to temporarily store JWT username between passwordHandler and sessionHandler.
type authKey string

// connKey uniquely identifies an SSH connection by its remote address.
// Used to track authenticated connections for status display and port forwarding.
type connKey string

func newAuthKey(username string, remoteAddr net.Addr) authKey {
	return authKey(fmt.Sprintf("%s@%s", username, remoteAddr.String()))
}

// sessionState tracks an active SSH session (shell, command, or subsystem like SFTP).
type sessionState struct {
	session     ssh.Session
	sessionType string
	jwtUsername string
}

type Server struct {
	sshServer  *ssh.Server
	listener   net.Listener
	mu         sync.RWMutex
	hostKeyPEM []byte

	// sessions tracks active SSH sessions (shell, command, SFTP).
	// These are created when a client opens a session channel and requests shell/exec/subsystem.
	sessions map[sessionKey]*sessionState

	// pendingAuthJWT temporarily stores JWT username during the auth→session handoff.
	// Populated in passwordHandler, consumed in sessionHandler/sftpSubsystemHandler.
	pendingAuthJWT map[authKey]string

	// connections tracks all SSH connections by their remote address.
	// Populated at authentication time, stores JWT username and port forwards for status display.
	connections map[connKey]*connState

	allowLocalPortForwarding  bool
	allowRemotePortForwarding bool
	allowRootLogin            bool
	allowSFTP                 bool
	jwtEnabled                bool

	netstackNet *netstack.Net

	wgAddress wgaddr.Address

	remoteForwardListeners map[forwardKey]net.Listener

	jwtValidator *jwt.Validator
	jwtExtractor *jwt.ClaimsExtractor
	jwtConfig    *JWTConfig

	authorizer *sshauth.Authorizer

	suSupportsPty    bool
	loginIsUtilLinux bool
}

type JWTConfig struct {
	Issuer       string
	KeysLocation string
	MaxTokenAge  int64
	Audiences    []string
}

// Config contains all SSH server configuration options
type Config struct {
	// JWT authentication configuration. If nil, JWT authentication is disabled
	JWT *JWTConfig

	// HostKey is the SSH server host key in PEM format
	HostKeyPEM []byte
}

// SessionInfo contains information about an active SSH session
type SessionInfo struct {
	Username      string
	RemoteAddress string
	Command       string
	JWTUsername   string
	PortForwards  []string
}

// New creates an SSH server instance with the provided host key and optional JWT configuration
// If jwtConfig is nil, JWT authentication is disabled
func New(config *Config) *Server {
	s := &Server{
		mu:                     sync.RWMutex{},
		hostKeyPEM:             config.HostKeyPEM,
		sessions:               make(map[sessionKey]*sessionState),
		pendingAuthJWT:         make(map[authKey]string),
		remoteForwardListeners: make(map[forwardKey]net.Listener),
		connections:            make(map[connKey]*connState),
		jwtEnabled:             config.JWT != nil,
		jwtConfig:              config.JWT,
		authorizer:             sshauth.NewAuthorizer(), // Initialize with empty config
	}

	return s
}

// Start runs the SSH server
func (s *Server) Start(ctx context.Context, addr netip.AddrPort) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sshServer != nil {
		return errors.New("SSH server is already running")
	}

	s.suSupportsPty = s.detectSuPtySupport(ctx)
	s.loginIsUtilLinux = s.detectUtilLinuxLogin(ctx)

	ln, addrDesc, err := s.createListener(ctx, addr)
	if err != nil {
		return fmt.Errorf("create listener: %w", err)
	}

	sshServer, err := s.createSSHServer(ln.Addr())
	if err != nil {
		s.closeListener(ln)
		return fmt.Errorf("create SSH server: %w", err)
	}

	s.listener = ln
	s.sshServer = sshServer
	log.Infof("SSH server started on %s", addrDesc)

	go func() {
		if err := sshServer.Serve(ln); err != nil && !errors.Is(err, ssh.ErrServerClosed) {
			log.Errorf("SSH server error: %v", err)
		}
	}()
	return nil
}

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

func (s *Server) closeListener(ln net.Listener) {
	if ln == nil {
		return
	}
	if err := ln.Close(); err != nil {
		log.Debugf("listener close error: %v", err)
	}
}

// Stop closes the SSH server
func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sshServer == nil {
		return nil
	}

	if err := s.sshServer.Close(); err != nil {
		log.Debugf("close SSH server: %v", err)
	}

	s.sshServer = nil
	s.listener = nil

	maps.Clear(s.sessions)
	maps.Clear(s.pendingAuthJWT)
	maps.Clear(s.connections)

	for _, listener := range s.remoteForwardListeners {
		if err := listener.Close(); err != nil {
			log.Debugf("close remote forward listener: %v", err)
		}
	}
	maps.Clear(s.remoteForwardListeners)

	return nil
}

// Addr returns the address the SSH server is listening on, or nil if the server is not running
func (s *Server) Addr() net.Addr {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.listener == nil {
		return nil
	}

	return s.listener.Addr()
}

// GetStatus returns the current status of the SSH server and active sessions.
func (s *Server) GetStatus() (enabled bool, sessions []SessionInfo) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	enabled = s.sshServer != nil
	reportedAddrs := make(map[string]bool)

	for _, state := range s.sessions {
		info := s.buildSessionInfo(state)
		reportedAddrs[info.RemoteAddress] = true
		sessions = append(sessions, info)
	}

	// Add authenticated connections without sessions (e.g., -N or port-forwarding only)
	for key, connState := range s.connections {
		remoteAddr := string(key)
		if reportedAddrs[remoteAddr] {
			continue
		}
		cmd := cmdNonInteractive
		if len(connState.portForwards) > 0 {
			cmd = cmdPortForwarding
		}
		sessions = append(sessions, SessionInfo{
			Username:      connState.username,
			RemoteAddress: remoteAddr,
			Command:       cmd,
			JWTUsername:   connState.jwtUsername,
			PortForwards:  connState.portForwards,
		})
	}

	return enabled, sessions
}

func (s *Server) buildSessionInfo(state *sessionState) SessionInfo {
	session := state.session
	cmd := state.sessionType
	if cmd == "" {
		cmd = safeLogCommand(session.Command())
	}

	remoteAddr := session.RemoteAddr().String()
	info := SessionInfo{
		Username:      session.User(),
		RemoteAddress: remoteAddr,
		Command:       cmd,
		JWTUsername:   state.jwtUsername,
	}

	connState, exists := s.connections[connKey(remoteAddr)]
	if !exists {
		return info
	}

	info.PortForwards = connState.portForwards
	if len(connState.portForwards) > 0 && (cmd == cmdInteractiveShell || cmd == cmdNonInteractive) {
		info.Command = cmdPortForwarding
	}

	return info
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

// UpdateSSHAuth updates the SSH fine-grained access control configuration
// This should be called when network map updates include new SSH auth configuration
func (s *Server) UpdateSSHAuth(config *sshauth.Config) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Reset JWT validator/extractor to pick up new userIDClaim
	s.jwtValidator = nil
	s.jwtExtractor = nil

	s.authorizer.Update(config)
}

// ensureJWTValidator initializes the JWT validator and extractor if not already initialized
func (s *Server) ensureJWTValidator() error {
	s.mu.RLock()
	if s.jwtValidator != nil && s.jwtExtractor != nil {
		s.mu.RUnlock()
		return nil
	}
	config := s.jwtConfig
	authorizer := s.authorizer
	s.mu.RUnlock()

	if config == nil {
		return fmt.Errorf("JWT config not set")
	}

	if len(config.Audiences) == 0 {
		return fmt.Errorf("JWT config has no audiences configured")
	}

	log.Debugf("Initializing JWT validator (issuer: %s, audiences: %v)", config.Issuer, config.Audiences)
	validator := jwt.NewValidator(
		config.Issuer,
		config.Audiences,
		config.KeysLocation,
		true,
	)

	// Use custom userIDClaim from authorizer if available
	extractorOptions := []jwt.ClaimsExtractorOption{
		jwt.WithAudience(config.Audiences[0]),
	}
	if authorizer.GetUserIDClaim() != "" {
		extractorOptions = append(extractorOptions, jwt.WithUserIDClaim(authorizer.GetUserIDClaim()))
		log.Debugf("Using custom user ID claim: %s", authorizer.GetUserIDClaim())
	}

	extractor := jwt.NewClaimsExtractor(extractorOptions...)

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.jwtValidator != nil && s.jwtExtractor != nil {
		return nil
	}

	s.jwtValidator = validator
	s.jwtExtractor = extractor

	log.Infof("JWT validator initialized successfully")
	return nil
}

func (s *Server) validateJWTToken(tokenString string) (*gojwt.Token, error) {
	s.mu.RLock()
	jwtValidator := s.jwtValidator
	jwtConfig := s.jwtConfig
	s.mu.RUnlock()

	if jwtValidator == nil {
		return nil, fmt.Errorf("JWT validator not initialized")
	}

	token, err := jwtValidator.ValidateAndParse(context.Background(), tokenString)
	if err != nil {
		if jwtConfig != nil {
			if claims, parseErr := s.parseTokenWithoutValidation(tokenString); parseErr == nil {
				return nil, fmt.Errorf("validate token (expected issuer=%s, audiences=%v, actual issuer=%v, audience=%v): %w",
					jwtConfig.Issuer, jwtConfig.Audiences, claims["iss"], claims["aud"], err)
			}
		}
		return nil, fmt.Errorf("validate token: %w", err)
	}

	if err := s.checkTokenAge(token, jwtConfig); err != nil {
		return nil, err
	}

	return token, nil
}

func (s *Server) checkTokenAge(token *gojwt.Token, jwtConfig *JWTConfig) error {
	if jwtConfig == nil {
		return nil
	}

	maxTokenAge := jwtConfig.MaxTokenAge
	if maxTokenAge <= 0 {
		maxTokenAge = DefaultJWTMaxTokenAge
	}

	claims, ok := token.Claims.(gojwt.MapClaims)
	if !ok {
		userID := extractUserID(token)
		return fmt.Errorf("token has invalid claims format (user=%s)", userID)
	}

	iat, ok := claims["iat"].(float64)
	if !ok {
		userID := extractUserID(token)
		return fmt.Errorf("token missing iat claim (user=%s)", userID)
	}

	issuedAt := time.Unix(int64(iat), 0)
	tokenAge := time.Since(issuedAt)
	maxAge := time.Duration(maxTokenAge) * time.Second
	if tokenAge > maxAge {
		userID := getUserIDFromClaims(claims)
		return fmt.Errorf("token expired for user=%s: age=%v, max=%v", userID, tokenAge, maxAge)
	}

	return nil
}

func (s *Server) extractAndValidateUser(token *gojwt.Token) (*auth.UserAuth, error) {
	s.mu.RLock()
	jwtExtractor := s.jwtExtractor
	s.mu.RUnlock()

	if jwtExtractor == nil {
		userID := extractUserID(token)
		return nil, fmt.Errorf("JWT extractor not initialized (user=%s)", userID)
	}

	userAuth, err := jwtExtractor.ToUserAuth(token)
	if err != nil {
		userID := extractUserID(token)
		return nil, fmt.Errorf("extract user from token (user=%s): %w", userID, err)
	}

	if !s.hasSSHAccess(&userAuth) {
		return nil, fmt.Errorf("user %s does not have SSH access permissions", userAuth.UserId)
	}

	return &userAuth, nil
}

func (s *Server) hasSSHAccess(userAuth *auth.UserAuth) bool {
	return userAuth.UserId != ""
}

func extractUserID(token *gojwt.Token) string {
	if token == nil {
		return "unknown"
	}
	claims, ok := token.Claims.(gojwt.MapClaims)
	if !ok {
		return "unknown"
	}
	return getUserIDFromClaims(claims)
}

func getUserIDFromClaims(claims gojwt.MapClaims) string {
	if sub, ok := claims["sub"].(string); ok && sub != "" {
		return sub
	}
	if userID, ok := claims["user_id"].(string); ok && userID != "" {
		return userID
	}
	if email, ok := claims["email"].(string); ok && email != "" {
		return email
	}
	return "unknown"
}

func (s *Server) parseTokenWithoutValidation(tokenString string) (map[string]interface{}, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}

	return claims, nil
}

func (s *Server) passwordHandler(ctx ssh.Context, password string) bool {
	osUsername := ctx.User()
	remoteAddr := ctx.RemoteAddr()
	logger := s.getRequestLogger(ctx)

	if err := s.ensureJWTValidator(); err != nil {
		logger.Errorf("JWT validator initialization failed: %v", err)
		return false
	}

	token, err := s.validateJWTToken(password)
	if err != nil {
		logger.Warnf("JWT authentication failed: %v", err)
		return false
	}

	userAuth, err := s.extractAndValidateUser(token)
	if err != nil {
		logger.Warnf("user validation failed: %v", err)
		return false
	}

	logger = logger.WithField("jwt_user", userAuth.UserId)

	s.mu.RLock()
	authorizer := s.authorizer
	s.mu.RUnlock()

	msg, err := authorizer.Authorize(userAuth.UserId, osUsername)
	if err != nil {
		logger.Warnf("SSH auth denied: %v", err)
		return false
	}

	logger.Infof("SSH auth %s", msg)

	key := newAuthKey(osUsername, remoteAddr)
	remoteAddrStr := ctx.RemoteAddr().String()
	s.mu.Lock()
	s.pendingAuthJWT[key] = userAuth.UserId
	s.connections[connKey(remoteAddrStr)] = &connState{
		username:    ctx.User(),
		remoteAddr:  ctx.RemoteAddr(),
		jwtUsername: userAuth.UserId,
	}
	s.mu.Unlock()

	return true
}

func (s *Server) addConnectionPortForward(username string, remoteAddr net.Addr, forwardAddr string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := connKey(remoteAddr.String())
	if state, exists := s.connections[key]; exists {
		if !slices.Contains(state.portForwards, forwardAddr) {
			state.portForwards = append(state.portForwards, forwardAddr)
		}
		return
	}

	// Connection not in connections (non-JWT auth path)
	s.connections[key] = &connState{
		username:     username,
		remoteAddr:   remoteAddr,
		portForwards: []string{forwardAddr},
		jwtUsername:  s.pendingAuthJWT[newAuthKey(username, remoteAddr)],
	}
}

func (s *Server) removeConnectionPortForward(remoteAddr net.Addr, forwardAddr string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, exists := s.connections[connKey(remoteAddr.String())]
	if !exists {
		return
	}

	state.portForwards = slices.DeleteFunc(state.portForwards, func(addr string) bool {
		return addr == forwardAddr
	})
}

// trackedConn wraps a net.Conn to detect when it closes
type trackedConn struct {
	net.Conn
	server     *Server
	remoteAddr string
	onceClose  sync.Once
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.onceClose.Do(func() {
		c.server.handleConnectionClose(c.remoteAddr)
	})
	return err
}

func (s *Server) handleConnectionClose(remoteAddr string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := connKey(remoteAddr)
	state, exists := s.connections[key]
	if exists && len(state.portForwards) > 0 {
		s.connLogger(state).Info("port forwarding connection closed")
	}
	delete(s.connections, key)
}

func (s *Server) connLogger(state *connState) *log.Entry {
	logger := log.WithField("session", fmt.Sprintf("%s@%s", state.username, state.remoteAddr))
	if state.jwtUsername != "" {
		logger = logger.WithField("jwt_user", state.jwtUsername)
	}
	return logger
}

func (s *Server) findSessionKeyByContext(ctx ssh.Context) sessionKey {
	if ctx == nil {
		return "unknown"
	}

	sshConn := ctx.Value(ssh.ContextKeyConn)
	if sshConn == nil {
		return "unknown"
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	for sessionKey, state := range s.sessions {
		if state.session.Context().Value(ssh.ContextKeyConn) == sshConn {
			return sessionKey
		}
	}

	if ctx.User() != "" && ctx.RemoteAddr() != nil {
		return sessionKey(fmt.Sprintf("%s@%s", ctx.User(), ctx.RemoteAddr().String()))
	}

	return "unknown"
}

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
		log.Warnf("SSH connection rejected: non-TCP address %s", remoteAddr)
		return nil
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
		log.Warnf("SSH connection rejected from non-NetBird IP %s", remoteIP)
		return nil
	}

	log.Infof("SSH connection from NetBird peer %s allowed", tcpAddr)
	return &trackedConn{
		Conn:       conn,
		server:     s,
		remoteAddr: conn.RemoteAddr().String(),
	}
}

func (s *Server) createSSHServer(addr net.Addr) (*ssh.Server, error) {
	if err := enableUserSwitching(); err != nil {
		log.Warnf("failed to enable user switching: %v", err)
	}

	serverVersion := fmt.Sprintf("%s-%s", detection.ServerIdentifier, version.NetbirdVersion())
	if s.jwtEnabled {
		serverVersion += " " + detection.JWTRequiredMarker
	}

	server := &ssh.Server{
		Addr:    addr.String(),
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
		ConnCallback: s.connectionValidator,
		Version:      serverVersion,
	}

	if s.jwtEnabled {
		server.PasswordHandler = s.passwordHandler
	}

	hostKeyPEM := ssh.HostKeyPEM(s.hostKeyPEM)
	if err := server.SetOption(hostKeyPEM); err != nil {
		return nil, fmt.Errorf("set host key: %w", err)
	}

	s.configurePortForwarding(server)
	return server, nil
}

func (s *Server) storeRemoteForwardListener(key forwardKey, ln net.Listener) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.remoteForwardListeners[key] = ln
}

func (s *Server) removeRemoteForwardListener(key forwardKey) bool {
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

func (s *Server) directTCPIPHandler(srv *ssh.Server, conn *cryptossh.ServerConn, newChan cryptossh.NewChannel, ctx ssh.Context) {
	logger := s.getRequestLogger(ctx)

	var payload struct {
		Host           string
		Port           uint32
		OriginatorAddr string
		OriginatorPort uint32
	}

	if err := cryptossh.Unmarshal(newChan.ExtraData(), &payload); err != nil {
		if err := newChan.Reject(cryptossh.ConnectionFailed, "parse payload"); err != nil {
			logger.Debugf("channel reject error: %v", err)
		}
		return
	}

	s.mu.RLock()
	allowLocal := s.allowLocalPortForwarding
	s.mu.RUnlock()

	if !allowLocal {
		logger.Warnf("local port forwarding denied for %s:%d: disabled", payload.Host, payload.Port)
		_ = newChan.Reject(cryptossh.Prohibited, "local port forwarding disabled")
		return
	}

	if err := s.checkPortForwardingPrivileges(ctx, "local", payload.Port); err != nil {
		logger.Warnf("local port forwarding denied for %s:%d: %v", payload.Host, payload.Port, err)
		_ = newChan.Reject(cryptossh.Prohibited, "insufficient privileges")
		return
	}

	forwardAddr := fmt.Sprintf("-L %s:%d", payload.Host, payload.Port)
	s.addConnectionPortForward(ctx.User(), ctx.RemoteAddr(), forwardAddr)
	logger.Infof("local port forwarding: %s:%d", payload.Host, payload.Port)

	ssh.DirectTCPIPHandler(srv, conn, newChan, ctx)
}
