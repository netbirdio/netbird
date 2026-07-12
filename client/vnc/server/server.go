//go:build !js && !ios && !android

package server

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/tun/netstack"

	sshauth "github.com/netbirdio/netbird/shared/sessionauth"
)

// Connection modes sent by the client in the session header.
const (
	ModeAttach  byte = 0 // Capture current display
	ModeSession byte = 1 // Virtual session as specified user
)

// RFB security-failure reason codes sent to the client. These prefixes are
// stable so clients can branch on them without parsing free text.
// Format: "CODE: human message".
const (
	RejectCodeAuthForbidden  = "AUTH_FORBIDDEN"
	RejectCodeSessionError   = "SESSION_ERROR"
	RejectCodeCapturerError  = "CAPTURER_ERROR"
	RejectCodeUnsupportedOS  = "UNSUPPORTED"
	RejectCodeBadRequest     = "BAD_REQUEST"
	RejectCodeNoConsoleUser  = "NO_CONSOLE_USER"
	RejectCodeApprovalDenied = "APPROVAL_DENIED"
	RejectCodeNoApprover     = "NO_APPROVER"
)

// EnvVNCDisableDownscale disables any platform-specific framebuffer
// downscaling (e.g. Retina 2:1). Set to 1/true to send the native resolution.
const EnvVNCDisableDownscale = "NB_VNC_DISABLE_DOWNSCALE"

// freshWindow is how long an on-demand capturer may reuse its last result
// before triggering a new capture. Short enough to feel responsive, long
// enough to coalesce bursty multi-session requests. 16 ms ~= 60 fps.
const freshWindow = 16 * time.Millisecond

// maxConcurrentVNCConns caps in-flight VNC connections. Each accepted
// connection consumes a handler goroutine, a tracking entry, and (after
// handshake) capturer/encoder resources, so an unauthenticated peer that
// dials in a tight loop could otherwise grow memory without bound. The
// limit covers the entire accept→handshake→session window; a slot is
// released only when the handler returns.
const maxConcurrentVNCConns = 64

// maxFramebufferDim caps the screen dimensions accepted from a capturer.
// RFB serialises width/height as u16, and the encoder allocates per-frame
// buffers proportional to width*height*4. 8192 keeps width*height*4 well
// under 2^31 so int math doesn't overflow on 32-bit builds, and is large
// enough to cover real-world multi-monitor desktops.
const maxFramebufferDim = 8192

// ScreenCapturer grabs desktop frames for the VNC server.
type ScreenCapturer interface {
	// Width returns the current screen width in pixels.
	Width() int
	// Height returns the current screen height in pixels.
	Height() int
	// Capture returns the current desktop as an RGBA image.
	Capture() (*image.RGBA, error)
}

// captureIntoer is implemented by capturers that can write directly into a
// caller-provided buffer, skipping the per-frame snapshot copy that the
// session would otherwise need to make. Linux and macOS implement this.
type captureIntoer interface {
	CaptureInto(dst *image.RGBA) error
}

// cursorSource is implemented by capturers that can report the platform
// cursor sprite so the session can emit it via the Cursor pseudo-encoding
// (RFB 7.7.4). serial bumps on shape changes; callers cache by serial.
type cursorSource interface {
	Cursor() (img *image.RGBA, hotX, hotY int, serial uint64, err error)
}

// cursorPositionSource adds the cursor's current screen-space position to
// cursorSource so the encoder can alpha-blend the sprite into the captured
// framebuffer for "show remote cursor" mode. Implementations should be
// cheap; most platforms already get the position alongside the sprite.
type cursorPositionSource interface {
	CursorPos() (x, y int, err error)
}

// errFrameUnchanged is returned by capturers that hash the raw source
// bytes (currently macOS) when the new frame is byte-identical to the
// last one, so the encoder can short-circuit to an empty update.
var errFrameUnchanged = errors.New("frame unchanged")

// InputInjector delivers keyboard and mouse events to the OS.
type InputInjector interface {
	// InjectKey simulates a key press or release. keysym is an X11 KeySym.
	InjectKey(keysym uint32, down bool)
	// InjectKeyScancode simulates a key press or release using the QEMU
	// scancode (PC AT set 1, high byte 0xE0 for extended keys). Layout-
	// independent: the server's local keyboard layout decides what
	// character the key produces. Implementations should fall back to
	// InjectKey(keysym, down) when they don't have a scancode mapping
	// for the given code; that's strictly no worse than the legacy path.
	InjectKeyScancode(scancode uint32, keysym uint32, down bool)
	// InjectPointer simulates mouse movement and button state.
	// buttonMask is the RFB ExtendedMouseButtons mask: bits 0-6 follow
	// the standard PointerEvent layout (left/middle/right/wheel),
	// bit 7 is mouse-back (X1), bit 8 is mouse-forward (X2).
	InjectPointer(buttonMask uint16, x, y, serverW, serverH int)
	// SetClipboard sets the system clipboard to the given text.
	SetClipboard(text string)
	// GetClipboard returns the current system clipboard text.
	GetClipboard() string
	// TypeText synthesizes the given text as keystrokes on the active
	// desktop. Used to push host clipboard content into a secure desktop
	// (Winlogon/UAC) where the clipboard is isolated. On platforms or
	// sessions without keystroke synthesis it may be a no-op.
	TypeText(text string)
}

// connectionHeader is sent by the client before the RFB handshake to specify
// the VNC session mode and authenticate.
type connectionHeader struct {
	mode     byte
	username string
	// clientStatic is the client's static X25519 public key learned from
	// the Noise handshake. Populated when identityVerified is true.
	clientStatic []byte
	// sessionID is the Windows session ID; 0 selects the console session.
	sessionID uint32
	// width and height request the virtual display geometry for session mode.
	// Zero means use the default.
	width  uint16
	height uint16
	// identityVerified is true when the Noise_IK handshake completed.
	identityVerified bool
}

// Server is the embedded VNC server that listens on the WireGuard interface.
// It supports two operating modes:
//   - Direct mode: captures the screen and handles VNC sessions in-process.
//     Used when running in a user session with desktop access.
//   - Service mode: proxies VNC connections to an agent process spawned in
//     the active console session. Used when running as a Windows service in
//     Session 0.
//
// Within direct mode, each connection can request one of two session modes
// via the connection header:
//   - Attach: capture the current physical display.
//   - Session: start a virtual Xvfb display as the requested user.
type Server struct {
	capturer    ScreenCapturer
	injector    InputInjector
	serviceMode bool
	disableAuth bool
	// localAddr is the NetBird WireGuard IP this server is bound to.
	localAddr netip.Addr
	// network is the NetBird overlay network.
	network netip.Prefix
	// localAddr6 and network6 are the v6 overlay address and network, set
	// when a v6 listener is added; zero when the overlay has no v6.
	localAddr6 netip.Addr
	network6   netip.Prefix
	log        *log.Entry

	mu       sync.Mutex
	listener net.Listener
	// extraListeners holds additional listeners (e.g. the v6 overlay), closed
	// alongside listener on Stop.
	extraListeners []net.Listener
	ctx            context.Context
	cancel         context.CancelFunc
	vmgr           virtualSessionManager
	authorizer     *sshauth.Authorizer
	netstackNet    *netstack.Net
	// agentToken holds the raw token bytes for agent-mode auth.
	agentToken []byte
	// invalidAgentToken latches when AgentTokenHex was provided but failed
	// to decode. Start refuses to listen in that case so the daemon never
	// silently downgrades the local IPC hop to unauthenticated access.
	invalidAgentToken bool
	// identityKey is the daemon's static X25519 private key used in the
	// Noise_IK handshake. Nil disables the handshake.
	identityKey []byte
	// identityPublic is the matching X25519 public key, derived once at
	// construction to avoid recomputing per handshake.
	identityPublic []byte

	sessionsMu   sync.Mutex
	sessionSeq   uint64
	sessions     map[uint64]ActiveSessionInfo
	sessionConns map[uint64]net.Conn
	// acceptedConns tracks every connection between Accept() and handler
	// return, including connections still in the connection-header /
	// handshake phase that have not yet been registered in sessionConns.
	// closeActiveSessions iterates this set so Stop() can interrupt
	// handshaking peers, not just post-handshake sessions.
	acceptedConns map[net.Conn]struct{}
	// connAuth holds the verified Noise_IK identity tied to each accepted
	// connection so a later UpdateVNCAuth call can revoke live sessions
	// whose authorization no longer holds. Populated by registerConnAuth
	// once authenticateSession succeeds; absent entries (e.g. disableAuth
	// or pre-handshake conns) are skipped at revocation time.
	connAuth map[net.Conn]connAuthInfo

	// connSem caps concurrent accepted connections (handshake + session).
	// Buffered with maxConcurrentVNCConns slots; accept loops try-acquire
	// before spawning a handler and release on handler return.
	connSem chan struct{}

	// sessionRecorder, when non-nil, receives a SessionTick periodically
	// during each VNC session and on session close. The engine wires
	// this to its metrics framework.
	sessionRecorder func(SessionTick)

	// requireApproval enables the per-connection user-accept gate. When
	// true and approver is nil (or returns an error), the connection is
	// rejected before any agent or session work.
	requireApproval bool
	// approver prompts the local user (via the daemon→UI event channel)
	// to accept or deny each incoming connection.
	approver Approver

	// preListener, when non-nil, replaces the TCP listener Start would
	// open; addr/network args to Start are ignored. Used by the agent's
	// Unix-socket path.
	preListener net.Listener
}

// connAuthInfo captures the Noise_IK-verified identity bound to a live
// connection so policy updates can re-check it and close sessions whose
// authorization was revoked. clientStatic is empty when auth was disabled
// for this connection, which signals that revocation does not apply.
type connAuthInfo struct {
	clientStatic []byte
	mode         byte
	username     string
}

// ActiveSessionInfo describes a currently connected VNC client.
type ActiveSessionInfo struct {
	RemoteAddress string
	Mode          string
	Username      string
	// UserID is the authenticated session identity (hashed user ID from
	// the Noise_IK static-key registration), empty when auth is disabled.
	UserID string
	// Initiator is the dashboard-supplied display name of the user who
	// minted the SessionPubKey, when known. Empty when auth is disabled
	// or the authorizer has no display-name mapping.
	Initiator string
}

// vncSession provides capturer and injector for a virtual display session.
type vncSession interface {
	Capturer() ScreenCapturer
	Injector() InputInjector
	Display() string
	ClientConnect()
	ClientDisconnect()
}

// virtualSessionManager is implemented by sessionManager on Linux.
type virtualSessionManager interface {
	// GetOrCreate returns an existing session for the user or starts a new one
	// with the requested geometry. width/height of 0 means use the default.
	GetOrCreate(username string, width, height uint16) (vncSession, error)
	StopAll()
}

// Config bundles the values the VNC server needs at construction time;
// fields are read once by New. AgentTokenHex is decoded internally; an
// invalid value is logged and treated as empty.
type Config struct {
	Capturer        ScreenCapturer
	Injector        InputInjector
	IdentityKey     []byte
	ServiceMode     bool
	SessionRecorder func(SessionTick)
	DisableAuth     bool
	AgentTokenHex   string
	NetstackNet     *netstack.Net
	// Listener, when set, is used instead of Start opening a TCP listener;
	// addr/network args to Start are then ignored. The agent uses this to
	// listen on a Unix socket.
	Listener net.Listener
	// RequireApproval gates each accepted connection on a user-side accept
	// prompt before the proxy/session starts. Requires Approver to be set;
	// otherwise the gate fails closed.
	RequireApproval bool
	// Approver brokers the per-connection prompt to the local user via the
	// daemon→UI event channel. Nil disables the gate.
	Approver Approver
}

// Approver decouples the VNC server from the approval broker. A non-nil
// error means "do not proceed".
type Approver interface {
	Request(ctx context.Context, info ApprovalInfo) (ApprovalDecision, error)
}

// ApprovalDecision carries the parts of the user's response the VNC
// server acts on. Accept is implicit (errors signal deny). ViewOnly puts
// the session into read-only mode: the server drops input events.
type ApprovalDecision struct {
	ViewOnly bool
}

// ApprovalInfo describes the pending connection passed to the approver.
// Fields are best-effort; any may be empty.
type ApprovalInfo struct {
	PeerName   string
	PeerPubKey string
	SourceIP   string
	Mode       string
	Username   string
	// Initiator is the display name of the user who initiated the
	// connection (typically the dashboard user). Resolved from the
	// Noise-verified client static pubkey.
	Initiator string
}

// New creates a VNC server from the provided Config. IdentityKey is the
// 32-byte X25519 private key used in the Noise_IK handshake; nil disables
// auth. The protocol-level VNC password scheme is not supported.
func New(cfg Config) *Server {
	s := &Server{
		capturer:        cfg.Capturer,
		injector:        cfg.Injector,
		identityKey:     cfg.IdentityKey,
		serviceMode:     cfg.ServiceMode,
		sessionRecorder: cfg.SessionRecorder,
		requireApproval: cfg.RequireApproval,
		approver:        cfg.Approver,
		disableAuth:     cfg.DisableAuth,
		netstackNet:     cfg.NetstackNet,
		preListener:     cfg.Listener,
		authorizer:      sshauth.NewAuthorizer(),
		log:             log.WithField("component", "vnc-server"),
		sessions:        make(map[uint64]ActiveSessionInfo),
		sessionConns:    make(map[uint64]net.Conn),
		acceptedConns:   make(map[net.Conn]struct{}),
		connAuth:        make(map[net.Conn]connAuthInfo),
		connSem:         make(chan struct{}, maxConcurrentVNCConns),
	}
	if len(cfg.IdentityKey) == 32 {
		pub, err := curve25519.X25519(cfg.IdentityKey, curve25519.Basepoint)
		if err == nil {
			s.identityPublic = pub
		} else {
			s.log.Warnf("derive identity public key: %v", err)
		}
	}
	if cfg.AgentTokenHex != "" {
		if b, err := hex.DecodeString(cfg.AgentTokenHex); err == nil {
			s.agentToken = b
		} else {
			s.invalidAgentToken = true
			s.log.Warnf("invalid agent token: %v", err)
		}
	}
	return s
}

// ActiveSessions returns a snapshot of currently connected VNC clients.
func (s *Server) ActiveSessions() []ActiveSessionInfo {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	out := make([]ActiveSessionInfo, 0, len(s.sessions))
	for _, info := range s.sessions {
		out = append(out, info)
	}
	return out
}

func (s *Server) addSession(info ActiveSessionInfo, conn net.Conn) uint64 {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	s.sessionSeq++
	id := s.sessionSeq
	s.sessions[id] = info
	s.sessionConns[id] = conn
	return id
}

func (s *Server) removeSession(id uint64) {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	delete(s.sessions, id)
	delete(s.sessionConns, id)
}

// closeActiveSessions closes every accepted connection so per-connection
// goroutines unblock from their Read loops and exit. Called from Stop to
// make sure clients see an immediate disconnect when the server is brought
// down. Iterates acceptedConns so handshaking connections that have not
// yet registered in sessionConns are also closed.
func (s *Server) closeActiveSessions() {
	s.sessionsMu.Lock()
	conns := make([]net.Conn, 0, len(s.acceptedConns))
	for c := range s.acceptedConns {
		conns = append(conns, c)
	}
	s.sessionsMu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

// trackConn registers a freshly accepted connection so Stop() can close
// it even before the session is registered in sessionConns.
func (s *Server) trackConn(c net.Conn) {
	s.sessionsMu.Lock()
	s.acceptedConns[c] = struct{}{}
	s.sessionsMu.Unlock()
}

// untrackConn forgets a connection once its handler is returning.
func (s *Server) untrackConn(c net.Conn) {
	s.sessionsMu.Lock()
	delete(s.acceptedConns, c)
	delete(s.connAuth, c)
	s.sessionsMu.Unlock()
}

// gateApproval prompts the local user to accept or deny conn before any
// session resources are allocated. On rejection the conn already received
// an RFB reject reason; the gate does not close it.
// gateApproval returns the user's decision when approval is enabled, or a
// zero decision when it isn't. On rejection it writes the RFB rejection
// message to conn and returns an error; the caller is responsible for
// logging it (this function does not log on its own).
func (s *Server) gateApproval(conn net.Conn, header *connectionHeader) (ApprovalDecision, error) {
	if !s.requireApproval {
		return ApprovalDecision{}, nil
	}
	if s.approver == nil {
		rejectConnection(conn, codeMessage(RejectCodeNoApprover, "approval required but no approver configured"))
		return ApprovalDecision{}, errors.New("approval required but no approver configured")
	}
	if s.serviceMode {
		if err := interactiveUserError(); err != nil {
			rejectConnection(conn, codeMessage(RejectCodeNoConsoleUser, "no interactive user session"))
			return ApprovalDecision{}, fmt.Errorf("no interactive user session: %w", err)
		}
	}
	info := ApprovalInfo{
		SourceIP: sourceIPString(conn.RemoteAddr()),
		Mode:     modeString(header.mode),
		Username: header.username,
	}
	if len(header.clientStatic) == 32 {
		info.PeerPubKey = hex.EncodeToString(header.clientStatic)
		if s.authorizer != nil {
			info.Initiator = s.authorizer.LookupSessionDisplayName(header.clientStatic)
		}
	}
	decision, err := s.approver.Request(s.ctx, info)
	if err != nil {
		rejectConnection(conn, codeMessage(RejectCodeApprovalDenied, "approval denied"))
		return ApprovalDecision{}, fmt.Errorf("approval: %w", err)
	}
	return decision, nil
}

// sourceIPString returns the IP portion of a remote address, or the full
// string when no port is present (e.g. unix sockets).
func sourceIPString(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	if ta, ok := addr.(*net.TCPAddr); ok && ta != nil {
		return ta.IP.String()
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

// registerConnAuth records the verified Noise_IK identity for a live
// connection so UpdateVNCAuth can later revoke it if policy changes.
// No-op when auth is disabled (e.g. agent-mode loopback connections).
//
// The original authorization check in authorizeSession and this
// registration are not atomic, so a concurrent UpdateVNCAuth can revoke
// the client's pubkey in between (revokeUnauthorizedSessions iterates
// connAuth and would miss this connection because it isn't registered
// yet). To close that window we re-run authenticateSession here under
// the same sessionsMu that revokeUnauthorizedSessions holds; if the
// caller's pubkey is no longer authorized at registration time, we
// refuse the registration and the caller tears the connection down.
func (s *Server) registerConnAuth(c net.Conn, header *connectionHeader) error {
	if s.disableAuth || header == nil || len(header.clientStatic) != 32 {
		return nil
	}
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	if _, err := s.authenticateSession(header); err != nil {
		return fmt.Errorf("authorization revoked before session registration: %w", err)
	}
	s.connAuth[c] = connAuthInfo{
		clientStatic: append([]byte(nil), header.clientStatic...),
		mode:         header.mode,
		username:     header.username,
	}
	return nil
}

// tryAcquireConnSlot returns true when a connection slot was successfully
// reserved. Releases must pair with releaseConnSlot. Returns false when
// the cap is already saturated; callers must close the connection.
func (s *Server) tryAcquireConnSlot() bool {
	select {
	case s.connSem <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *Server) releaseConnSlot() {
	select {
	case <-s.connSem:
	default:
	}
}

// revokeUnauthorizedSessions closes every live connection whose Noise-
// verified identity no longer authenticates under the current authorizer
// configuration. Called by UpdateVNCAuth after the new policy is applied.
func (s *Server) revokeUnauthorizedSessions() {
	if s.disableAuth {
		return
	}
	s.sessionsMu.Lock()
	victims := make([]net.Conn, 0)
	for c, info := range s.connAuth {
		if len(info.clientStatic) != 32 {
			continue
		}
		hdr := &connectionHeader{
			identityVerified: true,
			clientStatic:     info.clientStatic,
			mode:             info.mode,
			username:         info.username,
		}
		if _, err := s.authenticateSession(hdr); err != nil {
			victims = append(victims, c)
			s.log.Infof("revoking VNC session from %s: %v", c.RemoteAddr(), err)
		}
	}
	s.sessionsMu.Unlock()
	for _, c := range victims {
		_ = c.Close()
	}
}

// UpdateVNCAuth updates the fine-grained authorization configuration and
// closes any live session whose identity no longer authenticates under
// the new policy. Revocation is event-driven: there is no periodic
// re-check, so a session stays open until either the next UpdateVNCAuth
// call or normal disconnect.
func (s *Server) UpdateVNCAuth(config *sshauth.Config) {
	s.authorizer.Update(config)
	s.revokeUnauthorizedSessions()
}

// Start begins listening for VNC connections on the given address.
// network is the NetBird overlay prefix used to validate connection sources.
// When Config.Listener was supplied, addr and network are ignored and the
// pre-built listener is used (the per-session agent path).
func (s *Server) Start(ctx context.Context, addr netip.AddrPort, network netip.Prefix) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.listener != nil {
		return fmt.Errorf("server already running")
	}
	if s.invalidAgentToken {
		return fmt.Errorf("invalid agent token configuration")
	}

	s.ctx, s.cancel = context.WithCancel(ctx)
	s.vmgr = s.platformSessionManager()

	var listenDesc string
	switch {
	case s.preListener != nil:
		s.listener = s.preListener
		listenDesc = s.preListener.Addr().String()
	default:
		ln, desc, err := s.openOverlayListener(addr, network)
		if err != nil {
			return err
		}
		s.listener = ln
		listenDesc = desc
	}

	if s.serviceMode {
		s.platformInit()
	}

	if s.serviceMode {
		go s.serviceAcceptLoop(s.listener)
	} else {
		go s.acceptLoop(s.listener)
	}

	s.log.Infof("started on %s (service_mode=%v)", listenDesc, s.serviceMode)
	return nil
}

// AddListener opens an additional overlay listener (e.g. the v6 overlay
// address) and serves it with the same accept path as the primary listener.
// The server must already be running. Mirrors the primary listener's mode so
// service-mode connections still route through the per-session agent proxy.
func (s *Server) AddListener(_ context.Context, addr netip.AddrPort, network netip.Prefix) error {
	s.mu.Lock()
	if s.listener == nil {
		s.mu.Unlock()
		return fmt.Errorf("server not running")
	}
	ln, desc, err := s.openOverlayListener(addr, network)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	s.extraListeners = append(s.extraListeners, ln)
	serviceMode := s.serviceMode
	s.mu.Unlock()

	s.log.Infof("also listening on %s (service_mode=%v)", desc, serviceMode)
	if serviceMode {
		go s.serviceAcceptLoop(ln)
	} else {
		go s.acceptLoop(ln)
	}
	return nil
}

func (s *Server) openOverlayListener(addr netip.AddrPort, network netip.Prefix) (net.Listener, string, error) {
	if !network.IsValid() {
		return nil, "", fmt.Errorf("invalid overlay network prefix")
	}
	if addr.Addr().Is6() {
		s.localAddr6 = addr.Addr()
		s.network6 = network
	} else {
		s.localAddr = addr.Addr()
		s.network = network
	}
	if s.netstackNet != nil {
		ln, err := s.netstackNet.ListenTCPAddrPort(addr)
		if err != nil {
			return nil, "", fmt.Errorf("listen on netstack %s: %w", addr, err)
		}
		return ln, fmt.Sprintf("netstack %s", addr), nil
	}
	tcpAddr := net.TCPAddrFromAddrPort(addr)
	ln, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return nil, "", fmt.Errorf("listen on %s: %w", addr, err)
	}
	return ln, addr.String(), nil
}

// Stop shuts down the server and closes all connections.
func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}

	// Close the listener first so the accept loop exits and cannot
	// register any further connections in acceptedConns. Then close every
	// already-accepted connection so per-session serve goroutines unblock
	// and run their deferred conn.Close.
	var listenerErr error
	if s.listener != nil {
		listenerErr = s.listener.Close()
		s.listener = nil
	}
	for _, ln := range s.extraListeners {
		if err := ln.Close(); err != nil && listenerErr == nil {
			listenerErr = err
		}
	}
	s.extraListeners = nil
	s.closeActiveSessions()

	if s.vmgr != nil {
		s.vmgr.StopAll()
	}

	if s.serviceMode {
		s.platformShutdown()
	}

	if c, ok := s.capturer.(interface{ Close() }); ok {
		c.Close()
	}

	if listenerErr != nil {
		return fmt.Errorf("close VNC listener: %w", listenerErr)
	}

	s.log.Info("stopped")
	return nil
}

// acceptLoop handles VNC connections directly (user session mode).
func (s *Server) acceptLoop(ln net.Listener) {
	if ln == nil {
		return
	}
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

		// Track before any early-reject path so a concurrent Stop's
		// closeActiveSessions snapshot can never miss a just-accepted
		// socket and let it survive shutdown.
		s.trackConn(conn)
		if !s.tryAcquireConnSlot() {
			s.untrackConn(conn)
			s.log.Warnf("rejecting VNC connection from %s: %d concurrent connections in flight", conn.RemoteAddr(), maxConcurrentVNCConns)
			_ = conn.Close()
			continue
		}
		enableTCPKeepAlive(conn, s.log)
		go func(c net.Conn) {
			defer s.releaseConnSlot()
			defer s.untrackConn(c)
			s.handleConnection(c)
		}(conn)
	}
}

// vncKeepAlivePeriod controls how often TCP layer probes are sent on an
// idle connection. Default OS settings (2 hours) are too long for an
// interactive session: when the server-side host dies without sending FIN
// (power loss, network partition, hung kernel), the client only learns of
// the dead connection when the OS gives up on a probe. 30 s here means
// most clients notice within ~3 minutes worst case.
const vncKeepAlivePeriod = 30 * time.Second

// enableTCPKeepAlive turns on SO_KEEPALIVE on the underlying TCP socket.
// Non-TCP conns (e.g. the netstack-backed listener) are skipped silently;
// keepalive there is the netstack's concern.
func enableTCPKeepAlive(c net.Conn, log *log.Entry) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	if err := tc.SetKeepAlive(true); err != nil {
		log.Debugf("set keepalive: %v", err)
		return
	}
	if err := tc.SetKeepAlivePeriod(vncKeepAlivePeriod); err != nil {
		log.Debugf("set keepalive period: %v", err)
	}
}

func (s *Server) validateCapturer(capturer ScreenCapturer) error {
	// Quick check first: if already ready, return immediately.
	if capturer.Width() > 0 && capturer.Height() > 0 {
		return nil
	}
	// Capturer not ready: poke any retry loop that supports it so it doesn't
	// wait out its full backoff (e.g. macOS waiting for Screen Recording).
	if w, ok := capturer.(interface{ Wake() }); ok {
		w.Wake()
	}
	// Wait up to 5s for the capturer to become ready.
	for range 50 {
		time.Sleep(100 * time.Millisecond)
		if capturer.Width() > 0 && capturer.Height() > 0 {
			return nil
		}
	}
	return errors.New("no display available (check X11 / framebuffer on Linux/FreeBSD or Screen Recording permission on macOS)")
}

// isAllowedSource rejects connections from outside the NetBird overlay network
// and from the local WireGuard IP (prevents local privilege escalation).
// Matches the SSH server's connectionValidator logic.
func (s *Server) isAllowedSource(addr net.Addr) bool {
	// Unix-socket remotes (the agent path) are local IPC, gated by the
	// token, not by overlay membership.
	if _, ok := addr.(*net.UnixAddr); ok {
		return true
	}
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		s.log.Warnf("connection rejected: unsupported remote address type %T", addr)
		return false
	}

	remoteIP, ok := netip.AddrFromSlice(tcpAddr.IP)
	if !ok {
		s.log.Warnf("connection rejected: invalid remote IP %s", tcpAddr.IP)
		return false
	}
	remoteIP = remoteIP.Unmap()

	if remoteIP.IsLoopback() && s.localAddr.IsLoopback() {
		return true
	}

	if remoteIP == s.localAddr || (s.localAddr6.IsValid() && remoteIP == s.localAddr6) {
		s.log.Warnf("connection rejected from own IP %s", remoteIP)
		return false
	}

	if !s.network.IsValid() && !s.network6.IsValid() {
		s.log.Warnf("connection rejected: overlay network not configured")
		return false
	}
	inV4 := s.network.IsValid() && s.network.Contains(remoteIP)
	inV6 := s.network6.IsValid() && s.network6.Contains(remoteIP)
	if !inV4 && !inV6 {
		s.log.Warnf("connection rejected from non-NetBird IP %s", remoteIP)
		return false
	}

	return true
}

func (s *Server) handleConnection(conn net.Conn) {
	start := time.Now()
	connLog := s.log.WithField("remote", conn.RemoteAddr().String())

	if !s.isAllowedSource(conn.RemoteAddr()) {
		connLog.Info("VNC connection rejected: source not allowed")
		_ = conn.Close()
		return
	}
	ok, agentViewOnly := s.verifyAgentToken(conn, connLog)
	if !ok {
		connLog.Info("VNC connection rejected: agent token check failed")
		return
	}
	header, err := s.readConnectionHeader(conn)
	if err != nil {
		connLog.Infof("VNC connection rejected: header read failed: %v", err)
		_ = conn.Close()
		return
	}
	var sessionUserID string
	connLog, sessionUserID, ok = s.authorizeSession(conn, header, connLog)
	if !ok {
		connLog.Info("VNC connection rejected: auth failed")
		return
	}
	if err := s.registerConnAuth(conn, header); err != nil {
		rejectConnection(conn, codeMessage(RejectCodeAuthForbidden, err.Error()))
		connLog.Warnf("VNC connection rejected: %v", err)
		return
	}

	decision, err := s.gateApproval(conn, header)
	if err != nil {
		connLog.Infof("VNC connection rejected: %v", err)
		return
	}
	if decision.ViewOnly {
		connLog.Info("VNC connection approved by user (view-only)")
	} else if s.requireApproval {
		connLog.Info("VNC connection approved by user")
	}

	capturer, injector, sessionCleanup, ok := s.acquireSessionResources(conn, header, &connLog)
	if !ok {
		connLog.Warn("VNC connection rejected: capturer/injector unavailable")
		return
	}
	defer sessionCleanup()

	if err := s.validateCapturer(capturer); err != nil {
		rejectConnection(conn, codeMessage(RejectCodeCapturerError, fmt.Sprintf("screen capturer: %v", err)))
		connLog.Warnf("VNC connection rejected: capturer not ready: %v", err)
		return
	}

	// Validate framebuffer dimensions BEFORE registering the active
	// session: keeps a misbehaving capturer from briefly showing up in
	// ActiveSessions output and ensures the rest of the pipeline only
	// ever runs against an in-range frame.
	w, h := capturer.Width(), capturer.Height()
	if w <= 0 || h <= 0 || w > maxFramebufferDim || h > maxFramebufferDim {
		rejectConnection(conn, codeMessage(RejectCodeCapturerError, fmt.Sprintf("framebuffer dimensions out of range: %dx%d", w, h)))
		connLog.Warnf("VNC connection rejected: framebuffer %dx%d outside [1, %d]", w, h, maxFramebufferDim)
		return
	}

	var initiator string
	if s.authorizer != nil {
		initiator = s.authorizer.LookupSessionDisplayName(header.clientStatic)
	}
	sessionID := s.addSession(ActiveSessionInfo{
		RemoteAddress: conn.RemoteAddr().String(),
		Mode:          modeString(header.mode),
		Username:      header.username,
		UserID:        sessionUserID,
		Initiator:     initiator,
	}, conn)
	defer s.removeSession(sessionID)

	conn = newMetricsConn(conn, s.sessionRecorder)
	sess := &session{
		conn:     conn,
		capturer: capturer,
		injector: injector,
		serverW:  w,
		serverH:  h,
		log:      connLog,
		viewOnly: decision.ViewOnly || agentViewOnly,
	}
	sess.serve()
	connLog.Infof("VNC connection closed (%dms)", time.Since(start).Milliseconds())
}

// codeMessage formats a stable reject code with a human-readable message.
// Dashboards split on the first ": " to recover the code without parsing the
// free-text suffix.
func codeMessage(code, msg string) string {
	return code + ": " + msg
}

// rejectConnection sends a minimal RFB handshake with a security failure
// reason, so VNC clients display the error message instead of a generic
// "unexpected disconnect."
func rejectConnection(conn net.Conn, reason string) {
	defer conn.Close()
	// RFB 3.8 server version.
	if _, err := io.WriteString(conn, "RFB 003.008\n"); err != nil {
		return
	}
	// Read client version (12 bytes), ignore errors here so a short-lived
	// or pre-handshake client still gets the failure reason below.
	var clientVer [12]byte
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.ReadFull(conn, clientVer[:])
	_ = conn.SetReadDeadline(time.Time{})
	// Send 0 security types = connection failed, followed by reason.
	msg := []byte(reason)
	buf := make([]byte, 1+4+len(msg))
	buf[0] = 0 // 0 security types = failure
	binary.BigEndian.PutUint32(buf[1:5], uint32(len(msg)))
	copy(buf[5:], msg)
	_, _ = conn.Write(buf)
}

// acquireSessionResources returns the capturer/injector to use for this
// connection and a cleanup func to call when the session ends. ok is false
// when the connection was rejected (and the caller must just return).
func (s *Server) acquireSessionResources(conn net.Conn, header *connectionHeader, connLog **log.Entry) (ScreenCapturer, InputInjector, func(), bool) {
	switch header.mode {
	case ModeSession:
		return s.acquireVirtualSession(conn, header, connLog)
	default:
		capturer, cleanup := s.acquireAttachSession()
		return capturer, s.injector, cleanup, true
	}
}

func (s *Server) acquireVirtualSession(conn net.Conn, header *connectionHeader, connLog **log.Entry) (ScreenCapturer, InputInjector, func(), bool) {
	if s.vmgr == nil {
		rejectConnection(conn, codeMessage(RejectCodeUnsupportedOS, "virtual sessions not supported on this platform"))
		(*connLog).Warn("session rejected: not supported on this platform")
		return nil, nil, nil, false
	}
	if header.username == "" {
		rejectConnection(conn, codeMessage(RejectCodeBadRequest, "session mode requires a username"))
		(*connLog).Warn("session rejected: no username provided")
		return nil, nil, nil, false
	}
	vs, err := s.vmgr.GetOrCreate(header.username, header.width, header.height)
	if err != nil {
		rejectConnection(conn, codeMessage(RejectCodeSessionError, fmt.Sprintf("create virtual session: %v", err)))
		(*connLog).Warnf("create virtual session for %s: %v", header.username, err)
		return nil, nil, nil, false
	}
	vs.ClientConnect()
	*connLog = (*connLog).WithField("vnc_user", header.username)
	(*connLog).Infof("session mode: user=%s display=%s", header.username, vs.Display())
	return vs.Capturer(), vs.Injector(), vs.ClientDisconnect, true
}

// acquireAttachSession bumps the shared capturer's per-session refcount
// (if it implements the optional ClientConnect/ClientDisconnect pair) and
// returns a cleanup func that releases it. X11Poller and the Windows
// capturer rely on the disconnect path to drop SHM/DXGI resources when no
// client is active.
func (s *Server) acquireAttachSession() (ScreenCapturer, func()) {
	type connectDisconnect interface {
		ClientConnect()
		ClientDisconnect()
	}
	if cc, ok := s.capturer.(connectDisconnect); ok {
		cc.ClientConnect()
		return s.capturer, cc.ClientDisconnect
	}
	return s.capturer, func() { /* capturer has no per-client disconnect hook */ }
}

// modeString returns a human-readable session mode name.
func modeString(m byte) string {
	switch m {
	case ModeAttach:
		return "attach"
	case ModeSession:
		return "session"
	default:
		return "unknown"
	}
}
