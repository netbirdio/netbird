//go:build !js && !ios && !android

package server

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/tun/netstack"

	sshauth "github.com/netbirdio/netbird/client/ssh/auth"
	nbjwt "github.com/netbirdio/netbird/shared/auth/jwt"
)

// Connection modes sent by the client in the session header.
const (
	ModeAttach  byte = 0 // Capture current display
	ModeSession byte = 1 // Virtual session as specified user
)

// RFB security-failure reason codes sent to the client. These prefixes are
// stable so dashboard integrations can branch on them without parsing
// free text. Format: "CODE: human message".
const (
	RejectCodeJWTMissing    = "AUTH_JWT_MISSING"
	RejectCodeJWTExpired    = "AUTH_JWT_EXPIRED"
	RejectCodeJWTInvalid    = "AUTH_JWT_INVALID"
	RejectCodeAuthForbidden = "AUTH_FORBIDDEN"
	RejectCodeAuthConfig    = "AUTH_CONFIG"
	RejectCodeSessionError  = "SESSION_ERROR"
	RejectCodeCapturerError = "CAPTURER_ERROR"
	RejectCodeUnsupportedOS = "UNSUPPORTED"
	RejectCodeBadRequest    = "BAD_REQUEST"
	RejectCodeNoConsoleUser = "NO_CONSOLE_USER"
)

// EnvVNCDisableDownscale disables any platform-specific framebuffer
// downscaling (e.g. Retina 2:1). Set to 1/true to send the native resolution.
const EnvVNCDisableDownscale = "NB_VNC_DISABLE_DOWNSCALE"

// freshWindow is how long an on-demand capturer may reuse its last result
// before triggering a new capture. Short enough to feel responsive, long
// enough to coalesce bursty multi-session requests. 16 ms ~= 60 fps.
const freshWindow = 16 * time.Millisecond

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
	InjectPointer(buttonMask uint8, x, y, serverW, serverH int)
	// SetClipboard sets the system clipboard to the given text.
	SetClipboard(text string)
	// GetClipboard returns the current system clipboard text.
	GetClipboard() string
	// TypeText synthesizes the given text as keystrokes on the active
	// desktop. Used by the dashboard's Paste button to push host clipboard
	// content into a secure desktop (Winlogon/UAC) where the clipboard is
	// isolated. On platforms or sessions without keystroke synthesis it
	// may be a no-op.
	TypeText(text string)
}

// JWTConfig holds JWT validation configuration for VNC auth.
type JWTConfig struct {
	Issuer       string
	KeysLocation string
	MaxTokenAge  int64
	Audiences    []string
}

// connectionHeader is sent by the client before the RFB handshake to specify
// the VNC session mode and authenticate.
type connectionHeader struct {
	mode      byte
	username  string
	jwt       string
	sessionID uint32 // Windows session ID (0 = console/auto)
	// width and height request the virtual display geometry for session mode.
	// Zero means use the default.
	width  uint16
	height uint16
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
	localAddr   netip.Addr   // NetBird WireGuard IP this server is bound to
	network     netip.Prefix // NetBird overlay network
	log         *log.Entry

	mu           sync.Mutex
	listener     net.Listener
	ctx          context.Context
	cancel       context.CancelFunc
	vmgr         virtualSessionManager
	jwtConfig    *JWTConfig
	jwtValidator *nbjwt.Validator
	jwtExtractor *nbjwt.ClaimsExtractor
	authorizer   *sshauth.Authorizer
	netstackNet  *netstack.Net
	agentToken   []byte // raw token bytes for agent-mode auth

	sessionsMu   sync.Mutex
	sessionSeq   uint64
	sessions     map[uint64]ActiveSessionInfo
	sessionConns map[uint64]net.Conn

	// sessionRecorder, when non-nil, receives a SessionTick periodically
	// during each VNC session and on session close. The engine wires
	// this to its metrics framework.
	sessionRecorder func(SessionTick)
}

// ActiveSessionInfo describes a currently connected VNC client.
type ActiveSessionInfo struct {
	RemoteAddress string
	Mode          string
	Username      string
	JWTUsername   string
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

// New creates a VNC server with the given screen capturer and input injector.
// Authentication is handled by the dashboard JWT exchange after the RFB
// handshake; the protocol-level VNC password scheme is not supported.
func New(capturer ScreenCapturer, injector InputInjector) *Server {
	return &Server{
		capturer:   capturer,
		injector:   injector,
		authorizer: sshauth.NewAuthorizer(),
		log:        log.WithField("component", "vnc-server"),
		sessions:     make(map[uint64]ActiveSessionInfo),
		sessionConns: make(map[uint64]net.Conn),
	}
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

// closeActiveSessions closes every active session's connection so the
// per-session serve goroutines unblock from their Read loops and exit.
// Called from Stop to make sure clients see an immediate disconnect when
// the server is brought down, instead of waiting for the OS to reclaim
// the sockets after process exit.
func (s *Server) closeActiveSessions() {
	s.sessionsMu.Lock()
	conns := make([]net.Conn, 0, len(s.sessionConns))
	for _, c := range s.sessionConns {
		conns = append(conns, c)
	}
	s.sessionsMu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

// SetServiceMode enables proxy-to-agent mode for Windows service operation.
func (s *Server) SetServiceMode(enabled bool) {
	s.serviceMode = enabled
}

// SetSessionRecorder installs a callback that receives a SessionTick
// each sessionTickInterval during a VNC session and one final tick on
// session close. Pass nil to disable. Empty ticks (no wire activity)
// are skipped.
func (s *Server) SetSessionRecorder(recorder func(SessionTick)) {
	s.sessionRecorder = recorder
}

// SetJWTConfig configures JWT authentication for VNC connections.
// Pass nil to disable JWT (public mode).
func (s *Server) SetJWTConfig(config *JWTConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jwtConfig = config
	s.jwtValidator = nil
	s.jwtExtractor = nil
}

// SetDisableAuth disables authentication entirely.
func (s *Server) SetDisableAuth(disable bool) {
	s.disableAuth = disable
}

// SetAgentToken sets a hex-encoded token that must be presented by incoming
// connections before any VNC data. Used in agent mode to verify that only the
// trusted service process connects.
func (s *Server) SetAgentToken(hexToken string) {
	if hexToken == "" {
		return
	}
	b, err := hex.DecodeString(hexToken)
	if err != nil {
		s.log.Warnf("invalid agent token: %v", err)
		return
	}
	s.agentToken = b
}

// SetNetstackNet sets the netstack network for userspace-only listening.
// When set, the VNC server listens via netstack instead of a real OS socket.
func (s *Server) SetNetstackNet(n *netstack.Net) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.netstackNet = n
}

// UpdateVNCAuth updates the fine-grained authorization configuration.
func (s *Server) UpdateVNCAuth(config *sshauth.Config) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jwtValidator = nil
	s.jwtExtractor = nil
	s.authorizer.Update(config)
}

// Start begins listening for VNC connections on the given address.
// network is the NetBird overlay prefix used to validate connection sources.
func (s *Server) Start(ctx context.Context, addr netip.AddrPort, network netip.Prefix) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.listener != nil {
		return fmt.Errorf("server already running")
	}

	if !network.IsValid() {
		return fmt.Errorf("invalid overlay network prefix")
	}

	s.ctx, s.cancel = context.WithCancel(ctx)
	s.vmgr = s.platformSessionManager()
	s.localAddr = addr.Addr()
	s.network = network

	var listener net.Listener
	var listenDesc string
	if s.netstackNet != nil {
		ln, err := s.netstackNet.ListenTCPAddrPort(addr)
		if err != nil {
			return fmt.Errorf("listen on netstack %s: %w", addr, err)
		}
		listener = ln
		listenDesc = fmt.Sprintf("netstack %s", addr)
	} else {
		tcpAddr := net.TCPAddrFromAddrPort(addr)
		ln, err := net.ListenTCP("tcp", tcpAddr)
		if err != nil {
			return fmt.Errorf("listen on %s: %w", addr, err)
		}
		listener = ln
		listenDesc = addr.String()
	}
	s.listener = listener

	if s.serviceMode {
		s.platformInit()
	}

	if s.serviceMode {
		go s.serviceAcceptLoop()
	} else {
		go s.acceptLoop()
	}

	s.log.Infof("started on %s (service_mode=%v)", listenDesc, s.serviceMode)
	return nil
}

// Stop shuts down the server and closes all connections.
func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}

	// Close active client connections before tearing down capturers and
	// listeners. The per-session serve goroutines unblock from their Read
	// loop with an error and run their deferred conn.Close, which surfaces
	// a clean disconnect on the client side instead of leaving the
	// connection hanging until the OS reclaims it on process exit.
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

	if s.listener != nil {
		err := s.listener.Close()
		s.listener = nil
		if err != nil {
			return fmt.Errorf("close VNC listener: %w", err)
		}
	}

	s.log.Info("stopped")
	return nil
}

// acceptLoop handles VNC connections directly (user session mode).
func (s *Server) acceptLoop() {
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
		go s.handleConnection(conn)
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
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		s.log.Warnf("connection rejected: non-TCP address %s", addr)
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

	if remoteIP == s.localAddr {
		s.log.Warnf("connection rejected from own IP %s", remoteIP)
		return false
	}

	if !s.network.IsValid() {
		s.log.Warnf("connection rejected: overlay network not configured")
		return false
	}
	if !s.network.Contains(remoteIP) {
		s.log.Warnf("connection rejected from non-NetBird IP %s", remoteIP)
		return false
	}

	return true
}

func (s *Server) handleConnection(conn net.Conn) {
	connLog := s.log.WithField("remote", conn.RemoteAddr().String())

	if !s.isAllowedSource(conn.RemoteAddr()) {
		conn.Close()
		return
	}
	if !s.verifyAgentToken(conn, connLog) {
		return
	}
	header, err := readConnectionHeader(conn)
	if err != nil {
		connLog.Warnf("read connection header: %v", err)
		conn.Close()
		return
	}
	connLog, jwtUserID, ok := s.authorizeJWT(conn, header, connLog)
	if !ok {
		return
	}

	capturer, injector, sessionCleanup, ok := s.acquireSessionResources(conn, header, &connLog)
	if !ok {
		return
	}
	defer sessionCleanup()

	sessionID := s.addSession(ActiveSessionInfo{
		RemoteAddress: conn.RemoteAddr().String(),
		Mode:          modeString(header.mode),
		Username:      header.username,
		JWTUsername:   jwtUserID,
	}, conn)
	defer s.removeSession(sessionID)

	if err := s.validateCapturer(capturer); err != nil {
		rejectConnection(conn, codeMessage(RejectCodeCapturerError, fmt.Sprintf("screen capturer: %v", err)))
		connLog.Warnf("capturer not ready: %v", err)
		return
	}

	conn = newMetricsConn(conn, s.sessionRecorder)
	sess := &session{
		conn:     conn,
		capturer: capturer,
		injector: injector,
		serverW:  capturer.Width(),
		serverH:  capturer.Height(),
		log:      connLog,
		// Virtual sessions run on Xvfb which has no usable cursor source,
		// so we skip the Cursor pseudo-encoding and let the dashboard's
		// local fallback show instead.
		disableCursor: header.mode == ModeSession,
	}
	sess.serve()
}

// codeMessage formats a stable reject code with a human-readable message.
// Dashboards split on the first ": " to recover the code without parsing the
// free-text suffix.
func codeMessage(code, msg string) string {
	return code + ": " + msg
}

// jwtErrorCode maps a JWT auth error to a stable reject code.
func jwtErrorCode(err error) string {
	if err == nil {
		return RejectCodeJWTInvalid
	}
	if errors.Is(err, nbjwt.ErrTokenExpired) {
		return RejectCodeJWTExpired
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "JWT required but not provided"):
		return RejectCodeJWTMissing
	case strings.Contains(msg, "authorize") || strings.Contains(msg, "not authorized"):
		return RejectCodeAuthForbidden
	default:
		return RejectCodeJWTInvalid
	}
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

const defaultJWTMaxTokenAge = 10 * 60 // 10 minutes

// authenticateJWT validates the JWT from the connection header and checks
// authorization. For attach mode, just checks membership in the authorized
// user list. For session mode, additionally validates the OS user mapping.
func (s *Server) authenticateJWT(header *connectionHeader) (string, error) {
	if header.jwt == "" {
		return "", fmt.Errorf("JWT required but not provided")
	}

	s.mu.Lock()
	if err := s.ensureJWTValidator(); err != nil {
		s.mu.Unlock()
		return "", fmt.Errorf("initialize JWT validator: %w", err)
	}
	validator := s.jwtValidator
	extractor := s.jwtExtractor
	s.mu.Unlock()

	token, err := validator.ValidateAndParse(context.Background(), header.jwt)
	if err != nil {
		return "", fmt.Errorf("validate JWT: %w", err)
	}

	if err := s.checkTokenAge(token); err != nil {
		return "", err
	}

	userAuth, err := extractor.ToUserAuth(token)
	if err != nil {
		return "", fmt.Errorf("extract user from JWT: %w", err)
	}
	if userAuth.UserId == "" {
		return "", fmt.Errorf("JWT has no user ID")
	}

	switch header.mode {
	case ModeSession:
		// Session mode: check user + OS username mapping.
		if _, err := s.authorizer.Authorize(userAuth.UserId, header.username); err != nil {
			return "", fmt.Errorf("authorize session for %s: %w", header.username, err)
		}
	default:
		// Attach mode: just check user is in the authorized list (wildcard OS user).
		if _, err := s.authorizer.Authorize(userAuth.UserId, "*"); err != nil {
			return "", fmt.Errorf("user not authorized for VNC: %w", err)
		}
	}

	return userAuth.UserId, nil
}

// ensureJWTValidator lazily initializes the JWT validator. Must be called with mu held.
func (s *Server) ensureJWTValidator() error {
	if s.jwtValidator != nil && s.jwtExtractor != nil {
		return nil
	}
	if s.jwtConfig == nil {
		return fmt.Errorf("no JWT config")
	}

	// Enable IdP key refresh so JWKS rotations don't latch the validator
	// off until daemon restart.
	s.jwtValidator = nbjwt.NewValidator(
		s.jwtConfig.Issuer,
		s.jwtConfig.Audiences,
		s.jwtConfig.KeysLocation,
		true,
	)

	var opts []nbjwt.ClaimsExtractorOption
	if len(s.jwtConfig.Audiences) > 0 {
		opts = append(opts, nbjwt.WithAudience(s.jwtConfig.Audiences[0]))
	}
	if claim := s.authorizer.GetUserIDClaim(); claim != "" {
		opts = append(opts, nbjwt.WithUserIDClaim(claim))
	}
	s.jwtExtractor = nbjwt.NewClaimsExtractor(opts...)

	return nil
}

func (s *Server) checkTokenAge(token *gojwt.Token) error {
	maxAge := defaultJWTMaxTokenAge
	if s.jwtConfig != nil && s.jwtConfig.MaxTokenAge > 0 {
		maxAge = int(s.jwtConfig.MaxTokenAge)
	}
	return nbjwt.CheckTokenAge(token, time.Duration(maxAge)*time.Second)
}

// readConnectionHeader reads the NetBird VNC session header from the connection.
// Format: [mode: 1 byte] [username_len: 2 bytes BE] [username: N bytes]
//
//	[jwt_len: 2 bytes BE] [jwt: N bytes]
//
// Uses a short timeout: our WASM proxy sends the header immediately after
// connecting. Standard VNC clients don't send anything first (server speaks
// first in RFB), so they time out and get the default attach mode.
func readConnectionHeader(conn net.Conn) (*connectionHeader, error) {
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return nil, fmt.Errorf("set deadline: %w", err)
	}
	defer conn.SetReadDeadline(time.Time{}) //nolint:errcheck

	var hdr [3]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		// Timeout or error: assume no header, use attach mode.
		return &connectionHeader{mode: ModeAttach}, nil
	}

	// Restore a longer deadline for reading variable-length fields.
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, fmt.Errorf("set deadline: %w", err)
	}

	mode := hdr[0]
	usernameLen := binary.BigEndian.Uint16(hdr[1:3])

	var username string
	if usernameLen > 0 {
		if usernameLen > 256 {
			return nil, fmt.Errorf("username too long: %d", usernameLen)
		}
		buf := make([]byte, usernameLen)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return nil, fmt.Errorf("read username: %w", err)
		}
		username = string(buf)
	}

	// Read JWT token length and data.
	var jwtLenBuf [2]byte
	var jwtToken string
	if _, err := io.ReadFull(conn, jwtLenBuf[:]); err == nil {
		jwtLen := binary.BigEndian.Uint16(jwtLenBuf[:])
		if jwtLen >= 8192 {
			return nil, fmt.Errorf("jwt too long: %d (max 8191)", jwtLen)
		}
		if jwtLen > 0 {
			buf := make([]byte, jwtLen)
			if _, err := io.ReadFull(conn, buf); err != nil {
				return nil, fmt.Errorf("read JWT: %w", err)
			}
			jwtToken = string(buf)
		}
	}

	// Read optional Windows session ID (4 bytes BE). Missing = 0 (console/auto).
	var sessionID uint32
	var sidBuf [4]byte
	if _, err := io.ReadFull(conn, sidBuf[:]); err == nil {
		sessionID = binary.BigEndian.Uint32(sidBuf[:])
	}

	// Read optional requested viewport size (2x uint16 BE). Missing = 0 (default).
	var width, height uint16
	var geomBuf [4]byte
	if _, err := io.ReadFull(conn, geomBuf[:]); err == nil {
		width = binary.BigEndian.Uint16(geomBuf[0:2])
		height = binary.BigEndian.Uint16(geomBuf[2:4])
	}

	return &connectionHeader{
		mode:      mode,
		username:  username,
		jwt:       jwtToken,
		sessionID: sessionID,
		width:     width,
		height:    height,
	}, nil
}

// verifyAgentToken validates the agent token prefix when configured. Returns
// false when the token is invalid or unreadable; the connection is closed.
func (s *Server) verifyAgentToken(conn net.Conn, connLog *log.Entry) bool {
	if len(s.agentToken) == 0 {
		return true
	}
	buf := make([]byte, len(s.agentToken))
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		connLog.Debugf("set agent token deadline: %v", err)
		conn.Close()
		return false
	}
	if _, err := io.ReadFull(conn, buf); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			// Connect-then-close probes (port liveness checks) hit this
			// path on every dial; logging them would just flood the
			// daemon log without surfacing a real failure.
			connLog.Tracef("agent auth: read token: %v", err)
		} else {
			connLog.Warnf("agent auth: read token: %v", err)
		}
		conn.Close()
		return false
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		connLog.Debugf("clear agent token deadline: %v", err)
	}
	if subtle.ConstantTimeCompare(buf, s.agentToken) != 1 {
		connLog.Warn("agent auth: invalid token, rejecting")
		conn.Close()
		return false
	}
	return true
}

// authorizeJWT performs JWT validation when auth is enabled. Returns the
// enriched log entry, jwt user ID (empty when auth disabled), and ok=false
// if the connection was rejected.
func (s *Server) authorizeJWT(conn net.Conn, header *connectionHeader, connLog *log.Entry) (*log.Entry, string, bool) {
	if s.disableAuth {
		return connLog, "", true
	}
	if s.jwtConfig == nil {
		rejectConnection(conn, codeMessage(RejectCodeAuthConfig, "auth enabled but no identity provider configured"))
		connLog.Warn("auth rejected: no identity provider configured")
		return connLog, "", false
	}
	jwtUserID, err := s.authenticateJWT(header)
	if err != nil {
		rejectConnection(conn, codeMessage(jwtErrorCode(err), err.Error()))
		connLog.Warnf("auth rejected: %v", err)
		return connLog, "", false
	}
	return connLog.WithField("jwt_user", jwtUserID), jwtUserID, true
}

// acquireSessionResources returns the capturer/injector to use for this
// connection and a cleanup func to call when the session ends. ok is false
// when the connection was rejected (and the caller must just return).
func (s *Server) acquireSessionResources(conn net.Conn, header *connectionHeader, connLog **log.Entry) (ScreenCapturer, InputInjector, func(), bool) {
	switch header.mode {
	case ModeSession:
		return s.acquireVirtualSession(conn, header, connLog)
	default:
		return s.acquireAttachSession(), s.injector, attachSessionCleanup, true
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

func (s *Server) acquireAttachSession() ScreenCapturer {
	if cc, ok := s.capturer.(interface{ ClientConnect() }); ok {
		cc.ClientConnect()
	}
	return s.capturer
}

// attachSessionCleanup is the no-op cleanup used by attach mode. Returned as a
// named func rather than an inline closure so the empty body is unambiguous.
func attachSessionCleanup() {
	// Attach mode keeps the shared capturer; nothing to release per session.
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
