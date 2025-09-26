package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/gliderlabs/ssh"
	gojwt "github.com/golang-jwt/jwt/v5"
	log "github.com/sirupsen/logrus"
	cryptossh "golang.org/x/crypto/ssh"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/ssh/detection"
	"github.com/netbirdio/netbird/management/server/auth/jwt"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
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

// safeLogCommand returns a safe representation of the command for logging
func safeLogCommand(cmd []string) string {
	if len(cmd) == 0 {
		return "<empty>"
	}
	if len(cmd) == 1 {
		return cmd[0]
	}
	return fmt.Sprintf("%s [%d args]", cmd[0], len(cmd)-1)
}

type sshConnectionState struct {
	hasActivePortForward bool
	username             string
	remoteAddr           string
}

type Server struct {
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
	jwtEnabled                bool

	netstackNet *netstack.Net

	wgAddress wgaddr.Address
	ifIdx     int

	remoteForwardListeners map[ForwardKey]net.Listener
	sshConnections         map[*cryptossh.ServerConn]*sshConnectionState

	jwtValidator          *jwt.Validator
	jwtExtractor          *jwt.ClaimsExtractor
	jwtConfig             *JWTConfig
	authenticatedSessions map[string]*AuthenticatedSession
}

type JWTConfig struct {
	Issuer       string
	Audience     string
	KeysLocation string
	MaxTokenAge  int64 // Maximum age of JWT tokens in seconds
}

type AuthenticatedSession struct {
	UserID    string
	Token     string
	ExpiresAt time.Time
}

type jwtAuthRequest struct {
	Token string `json:"token"`
}

// New creates an SSH server instance with the provided host key and optional JWT configuration
// If jwtConfig is nil, JWT authentication is disabled
func New(hostKeyPEM []byte, jwtConfig *JWTConfig) *Server {
	s := &Server{
		mu:                     sync.RWMutex{},
		hostKeyPEM:             hostKeyPEM,
		authorizedKeys:         make(map[string]ssh.PublicKey),
		sessions:               make(map[SessionKey]ssh.Session),
		remoteForwardListeners: make(map[ForwardKey]net.Listener),
		sshConnections:         make(map[*cryptossh.ServerConn]*sshConnectionState),
		authenticatedSessions:  make(map[string]*AuthenticatedSession),
		jwtEnabled:             jwtConfig != nil,
		jwtConfig:              jwtConfig,
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

	ln, addrDesc, err := s.createListener(ctx, addr)
	if err != nil {
		return fmt.Errorf("create listener: %w", err)
	}

	sshServer, err := s.createSSHServer(ln.Addr())
	if err != nil {
		s.cleanupOnError(ln)
		return fmt.Errorf("create SSH server: %w", err)
	}

	s.sshServer = sshServer
	log.Infof("SSH server started on %s", addrDesc)

	go func() {
		if err := sshServer.Serve(ln); !isShutdownError(err) {
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
	if err := ln.Close(); err != nil {
		log.Debugf("listener close error: %v", err)
	}
}

func (s *Server) cleanupOnError(ln net.Listener) {
	if s.ifIdx == 0 || ln == nil {
		return
	}

	s.closeListener(ln)
}

// Stop closes the SSH server
func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sshServer == nil {
		return nil
	}

	if err := s.sshServer.Close(); err != nil && !isShutdownError(err) {
		return fmt.Errorf("shutdown SSH server: %w", err)
	}

	s.sshServer = nil

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

// ensureJWTValidator initializes the JWT validator and extractor if not already initialized
func (s *Server) ensureJWTValidator() error {
	s.mu.RLock()
	if s.jwtValidator != nil && s.jwtExtractor != nil {
		s.mu.RUnlock()
		return nil
	}
	config := s.jwtConfig
	s.mu.RUnlock()

	if config == nil {
		return fmt.Errorf("JWT config not set")
	}

	log.Debugf("Initializing JWT validator (issuer: %s, audience: %s)", config.Issuer, config.Audience)

	validator := jwt.NewValidator(
		config.Issuer,
		[]string{config.Audience},
		config.KeysLocation,
		true,
	)

	extractor := jwt.NewClaimsExtractor(
		jwt.WithAudience(config.Audience),
	)

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

// handleJWTAuthRequest handles JWT authentication requests from SSH clients
func (s *Server) handleJWTAuthRequest(ctx ssh.Context, _ *ssh.Server, req *cryptossh.Request) (bool, []byte) {
	if ok, msg := s.checkJWTEnabled(ctx); !ok {
		return false, msg
	}

	if err := s.ensureJWTValidator(); err != nil {
		log.Errorf("Failed to initialize JWT validator: %v", err)
		return false, []byte("JWT authentication not available")
	}

	authReq, ok, msg := s.parseJWTAuthRequest(req)
	if !ok {
		return false, msg
	}

	token, ok, msg := s.validateJWTToken(ctx, authReq.Token)
	if !ok {
		return false, msg
	}

	userAuth, ok, msg := s.extractAndValidateUser(token)
	if !ok {
		return false, msg
	}

	sessionID := s.createAuthenticatedSession(ctx, authReq.Token, userAuth.UserId)
	log.WithField("session", sessionID).Infof("JWT authentication successful for user %s from %s", userAuth.UserId, ctx.RemoteAddr())
	return true, []byte("authentication successful")
}

func (s *Server) checkJWTEnabled(ctx ssh.Context) (bool, []byte) {
	s.mu.RLock()
	jwtEnabled := s.jwtEnabled
	s.mu.RUnlock()

	if !jwtEnabled {
		log.Debugf("JWT authentication request from %s rejected: JWT not enabled on SSH server", ctx.RemoteAddr())
		return false, []byte("JWT authentication not enabled")
	}
	return true, nil
}

func (s *Server) parseJWTAuthRequest(req *cryptossh.Request) (*jwtAuthRequest, bool, []byte) {
	var authReq jwtAuthRequest

	if err := json.Unmarshal(req.Payload, &authReq); err != nil {
		log.Errorf("Failed to parse JWT auth request: %v", err)
		return nil, false, []byte("invalid request format")
	}
	return &authReq, true, nil
}

func (s *Server) validateJWTToken(ctx ssh.Context, tokenString string) (*gojwt.Token, bool, []byte) {
	s.mu.RLock()
	jwtValidator := s.jwtValidator
	jwtConfig := s.jwtConfig
	s.mu.RUnlock()

	if jwtValidator == nil {
		log.Errorf("JWT validator is nil despite JWT being enabled - denying access")
		return nil, false, []byte("JWT authentication not available")
	}

	token, err := jwtValidator.ValidateAndParse(context.Background(), tokenString)
	if err != nil {
		s.logValidationFailure(ctx, tokenString, jwtConfig, err)
		return nil, false, []byte("token validation failed")
	}

	if ok, msg := s.checkTokenAge(ctx, token, jwtConfig); !ok {
		return nil, false, msg
	}

	return token, true, nil
}

func (s *Server) logValidationFailure(ctx ssh.Context, tokenString string, jwtConfig *JWTConfig, err error) {
	log.Errorf("JWT validation failed for user %s from %s: %v", ctx.User(), ctx.RemoteAddr(), err)
	if jwtConfig != nil {
		log.Debugf("JWT config - Expected Issuer: %s, Expected Audience: %s", jwtConfig.Issuer, jwtConfig.Audience)
	}
	if claims, parseErr := s.parseTokenWithoutValidation(tokenString); parseErr == nil {
		log.Debugf("JWT token claims - Actual Issuer: %v, Actual Audience: %v", claims["iss"], claims["aud"])
	}
}

func (s *Server) checkTokenAge(ctx ssh.Context, token *gojwt.Token, jwtConfig *JWTConfig) (bool, []byte) {
	if jwtConfig == nil || jwtConfig.MaxTokenAge <= 0 {
		return true, nil
	}

	claims, ok := token.Claims.(gojwt.MapClaims)
	if !ok {
		return true, nil
	}

	iat, ok := claims["iat"].(float64)
	if !ok {
		return true, nil
	}

	issuedAt := time.Unix(int64(iat), 0)
	tokenAge := time.Since(issuedAt)
	if tokenAge > time.Duration(jwtConfig.MaxTokenAge)*time.Second {
		log.Errorf("JWT token too old based on iat claim for user %s from %s: age=%v, max=%v",
			ctx.User(), ctx.RemoteAddr(), tokenAge, time.Duration(jwtConfig.MaxTokenAge)*time.Second)
		return false, []byte("token expired")
	}

	return true, nil
}

func (s *Server) extractAndValidateUser(token *gojwt.Token) (*nbcontext.UserAuth, bool, []byte) {
	s.mu.RLock()
	jwtExtractor := s.jwtExtractor
	s.mu.RUnlock()

	if jwtExtractor == nil {
		log.Errorf("JWT extractor is nil despite JWT being enabled - denying access")
		return nil, false, []byte("JWT authentication not available")
	}

	userAuth, err := jwtExtractor.ToUserAuth(token)
	if err != nil {
		log.Errorf("Failed to extract user auth from token: %v", err)
		return nil, false, []byte("token processing failed")
	}

	if !s.hasSSHAccess(&userAuth) {
		log.Errorf("User %s does not have SSH access permissions", userAuth.UserId)
		return nil, false, []byte("insufficient permissions")
	}

	return &userAuth, true, nil
}

func (s *Server) createAuthenticatedSession(ctx ssh.Context, token, userID string) string {
	sessionID := s.generateSessionID(ctx)
	s.mu.Lock()
	s.authenticatedSessions[sessionID] = &AuthenticatedSession{
		UserID:    userID,
		Token:     token,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	s.mu.Unlock()
	return sessionID
}

func (s *Server) generateSessionID(ctx ssh.Context) string {
	return fmt.Sprintf("%s@%s", ctx.User(), ctx.RemoteAddr().String())
}

func (s *Server) hasSSHAccess(userAuth *nbcontext.UserAuth) bool {
	return userAuth.UserId != ""
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

func (s *Server) isSessionAuthenticated(ctx ssh.Context) bool {
	s.mu.RLock()
	jwtEnabled := s.jwtEnabled
	s.mu.RUnlock()

	if !jwtEnabled {
		return true
	}

	if err := s.ensureJWTValidator(); err != nil {
		log.Errorf("Failed to ensure JWT validator: %v", err)
		return false
	}

	s.mu.RLock()
	jwtValidator := s.jwtValidator
	s.mu.RUnlock()

	if jwtValidator == nil {
		log.Errorf("JWT validator is nil despite JWT being enabled - denying access")
		return false
	}

	sessionID := s.generateSessionID(ctx)
	s.mu.RLock()
	session, exists := s.authenticatedSessions[sessionID]
	s.mu.RUnlock()

	if !exists {
		return false
	}

	if time.Now().After(session.ExpiresAt) {
		s.mu.Lock()
		delete(s.authenticatedSessions, sessionID)
		s.mu.Unlock()
		return false
	}

	return true
}

func (s *Server) publicKeyHandler(ctx ssh.Context, key ssh.PublicKey) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, allowed := range s.authorizedKeys {
		if ssh.KeysEqual(allowed, key) {
			if ctx != nil {
				log.Debugf("SSH public key authentication successful for user %s from %s (key type: %s)", ctx.User(), ctx.RemoteAddr(), key.Type())
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

func (s *Server) connectionCloseHandler(conn net.Conn, err error) {
	// We can't extract the SSH connection from net.Conn directly
	// Connection cleanup will happen during session cleanup or via timeout
	log.Debugf("SSH connection failed for %s: %v", conn.RemoteAddr(), err)
}

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
		log.Debugf("Using temporary session key for early port forward tracking: %s (will be updated when session established)", tempKey)
		return tempKey
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
		log.Debugf("SSH connection from non-TCP address %s allowed (skipping NetBird network validation)", remoteAddr)
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
		log.Warnf("SSH connection rejected from non-NetBird IP %s", remoteIP)
		return nil
	}

	log.Debugf("SSH connection from NetBird peer %s allowed", remoteIP)
	return conn
}

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

func (s *Server) createSSHServer(addr net.Addr) (*ssh.Server, error) {
	if err := enableUserSwitching(); err != nil {
		log.Warnf("failed to enable user switching: %v", err)
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
			"netbird-auth":         s.handleJWTAuthRequest,
			"netbird-detect":       s.handleDetectionRequest,
		},
		ConnCallback:             s.connectionValidator,
		ConnectionFailedCallback: s.connectionCloseHandler,
		Version:                  fmt.Sprintf("NetBird-SSH-%s", version.NetbirdVersion()),
	}

	// JWT authentication is handled via request handlers, not auth handlers
	// This allows "none" authentication while still validating JWT tokens

	hostKeyPEM := ssh.HostKeyPEM(s.hostKeyPEM)
	if err := server.SetOption(hostKeyPEM); err != nil {
		return nil, fmt.Errorf("set host key: %w", err)
	}

	s.configurePortForwarding(server)
	return server, nil
}

func (s *Server) handleDetectionRequest(_ ssh.Context, _ *ssh.Server, _ *cryptossh.Request) (bool, []byte) {
	response := fmt.Sprintf("%s-%s", detection.ServerIdentifier, version.NetbirdVersion())
	if s.jwtEnabled {
		response += " " + detection.JWTRequiredMarker
	}

	return true, []byte(response)
}

func (s *Server) storeRemoteForwardListener(key ForwardKey, ln net.Listener) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.remoteForwardListeners[key] = ln
}

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
