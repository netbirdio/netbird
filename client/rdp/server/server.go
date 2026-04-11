package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	sshauth "github.com/netbirdio/netbird/client/ssh/auth"
)

const (
	// InternalRDPAuthPort is the port the sideband auth server listens on.
	InternalRDPAuthPort = 22338

	// DefaultRDPAuthPort is the external port on the WireGuard interface (DNAT target).
	DefaultRDPAuthPort = 22338

	// maxRequestSize is the maximum size of an auth request in bytes.
	maxRequestSize = 64 * 1024

	// connectionTimeout is the timeout for a single auth connection.
	connectionTimeout = 30 * time.Second
)

// JWTValidator validates JWT tokens and extracts user identity.
type JWTValidator interface {
	ValidateAndExtract(token string) (userID string, err error)
}

// Authorizer checks if a user is authorized for RDP access.
type Authorizer interface {
	Authorize(jwtUserID, osUsername string) (string, error)
}

// Server is the sideband RDP authorization server that listens on the WireGuard interface.
type Server struct {
	listener     net.Listener
	pending      *PendingStore
	pipeServer   PipeServer
	jwtValidator JWTValidator
	authorizer   Authorizer
	sshAuthorizer *sshauth.Authorizer // reuses SSH ACL for RDP access control
	networkAddr  netip.Prefix // WireGuard network for source IP validation

	mu     sync.Mutex
	ctx    context.Context
	cancel context.CancelFunc
}

// PipeServer is the interface for the named pipe IPC server (platform-specific).
type PipeServer interface {
	Start(ctx context.Context) error
	Stop() error
}

// Config holds the configuration for the RDP auth server.
type Config struct {
	JWTValidator JWTValidator
	Authorizer   Authorizer
	NetworkAddr  netip.Prefix
	SessionTTL   time.Duration
}

// New creates a new RDP sideband auth server.
func New(cfg *Config) *Server {
	ttl := cfg.SessionTTL
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}

	pending := NewPendingStore(ttl)

	return &Server{
		pending:       pending,
		pipeServer:    newPipeServer(pending),
		jwtValidator:  cfg.JWTValidator,
		authorizer:    cfg.Authorizer,
		sshAuthorizer: sshauth.NewAuthorizer(),
		networkAddr:   cfg.NetworkAddr,
	}
}

// UpdateRDPAuth updates the RDP authorization config (reuses SSH ACL).
func (s *Server) UpdateRDPAuth(config *sshauth.Config) {
	s.sshAuthorizer.Update(config)
	log.Debugf("RDP auth: updated authorization config")
}

// Start begins listening for sideband auth requests on the given address.
func (s *Server) Start(ctx context.Context, addr netip.AddrPort) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.listener != nil {
		return errors.New("RDP auth server already running")
	}

	s.ctx, s.cancel = context.WithCancel(ctx)

	listenAddr := net.TCPAddrFromAddrPort(addr)
	listener, err := net.ListenTCP("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}
	s.listener = listener

	s.pending.StartCleanup(s.ctx)

	if s.pipeServer != nil {
		if err := s.pipeServer.Start(s.ctx); err != nil {
			log.Warnf("failed to start RDP named pipe server: %v", err)
		}
	}

	go s.acceptLoop()

	log.Infof("RDP sideband auth server started on %s", addr)
	return nil
}

// Stop shuts down the server and cleans up resources.
func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cancel != nil {
		s.cancel()
	}

	if s.pipeServer != nil {
		if err := s.pipeServer.Stop(); err != nil {
			log.Warnf("failed to stop RDP named pipe server: %v", err)
		}
	}

	if s.listener != nil {
		err := s.listener.Close()
		s.listener = nil
		if err != nil {
			return fmt.Errorf("close listener: %w", err)
		}
	}

	log.Info("RDP sideband auth server stopped")
	return nil
}

// GetPendingStore returns the pending session store (for testing/named pipe access).
func (s *Server) GetPendingStore() *PendingStore {
	return s.pending
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.ctx.Err() != nil {
				return
			}
			log.Debugf("RDP auth accept error: %v", err)
			continue
		}

		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer func() {
		if err := conn.Close(); err != nil {
			log.Debugf("RDP auth close connection: %v", err)
		}
	}()

	if err := conn.SetDeadline(time.Now().Add(connectionTimeout)); err != nil {
		log.Debugf("RDP auth set deadline: %v", err)
		return
	}

	// Validate source IP is from WireGuard network
	remoteAddr, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil {
		log.Debugf("RDP auth parse remote addr: %v", err)
		return
	}

	if !s.networkAddr.Contains(remoteAddr.Addr()) {
		log.Warnf("RDP auth rejected connection from non-WG address: %s", remoteAddr.Addr())
		return
	}

	// Read request
	data, err := io.ReadAll(io.LimitReader(conn, maxRequestSize))
	if err != nil {
		log.Debugf("RDP auth read request: %v", err)
		return
	}

	var req AuthRequest
	if err := json.Unmarshal(data, &req); err != nil {
		log.Debugf("RDP auth unmarshal request: %v", err)
		s.sendResponse(conn, &AuthResponse{Status: StatusDenied, Reason: "invalid request format"})
		return
	}

	response := s.processAuthRequest(remoteAddr.Addr(), &req)
	s.sendResponse(conn, response)
}

func (s *Server) processAuthRequest(peerIP netip.Addr, req *AuthRequest) *AuthResponse {
	// Validate JWT
	if s.jwtValidator == nil {
		// No JWT validation configured - for POC, accept all requests from WG peers
		log.Warnf("RDP auth: no JWT validator configured, accepting request from %s", peerIP)
		return s.createSession(peerIP, req, "no-jwt-validation")
	}

	userID, err := s.jwtValidator.ValidateAndExtract(req.JWTToken)
	if err != nil {
		log.Warnf("RDP auth JWT validation failed for %s: %v", peerIP, err)
		return &AuthResponse{Status: StatusDenied, Reason: "JWT validation failed"}
	}

	// Check authorization - try explicit authorizer first, then SSH ACL
	if s.authorizer != nil {
		if _, err := s.authorizer.Authorize(userID, req.RequestedUser); err != nil {
			log.Warnf("RDP auth denied for user %s -> %s: %v", userID, req.RequestedUser, err)
			return &AuthResponse{Status: StatusDenied, Reason: "not authorized for this user"}
		}
	} else if s.sshAuthorizer != nil {
		if _, err := s.sshAuthorizer.Authorize(userID, req.RequestedUser); err != nil {
			log.Warnf("RDP auth denied (SSH ACL) for user %s -> %s: %v", userID, req.RequestedUser, err)
			return &AuthResponse{Status: StatusDenied, Reason: "not authorized for this user"}
		}
	}

	return s.createSession(peerIP, req, userID)
}

func (s *Server) createSession(peerIP netip.Addr, req *AuthRequest, jwtUserID string) *AuthResponse {
	// Parse domain from requested user (DOMAIN\user or user@domain)
	osUser, domain := parseWindowsUsername(req.RequestedUser)

	session, err := s.pending.Add(peerIP, osUser, domain, jwtUserID, req.Nonce)
	if err != nil {
		log.Warnf("RDP auth create session failed: %v", err)
		return &AuthResponse{Status: StatusDenied, Reason: err.Error()}
	}

	return &AuthResponse{
		Status:    StatusAuthorized,
		SessionID: session.SessionID,
		ExpiresAt: session.ExpiresAt.Unix(),
		OSUser:    session.OSUsername,
	}
}

func (s *Server) sendResponse(conn net.Conn, resp *AuthResponse) {
	data, err := json.Marshal(resp)
	if err != nil {
		log.Debugf("RDP auth marshal response: %v", err)
		return
	}

	if _, err := conn.Write(data); err != nil {
		log.Debugf("RDP auth write response: %v", err)
	}
}

// parseWindowsUsername extracts username and domain from Windows username formats.
// Supports DOMAIN\username, username@domain, and plain username.
func parseWindowsUsername(fullUsername string) (username, domain string) {
	for i := len(fullUsername) - 1; i >= 0; i-- {
		if fullUsername[i] == '\\' {
			return fullUsername[i+1:], fullUsername[:i]
		}
	}

	if idx := indexOf(fullUsername, '@'); idx != -1 {
		return fullUsername[:idx], fullUsername[idx+1:]
	}

	return fullUsername, "."
}

func indexOf(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}
