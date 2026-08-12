//go:build android

package android

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/auth"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	nbssh "github.com/netbirdio/netbird/client/ssh"
	"github.com/netbirdio/netbird/client/ssh/detection"
)

const (
	sshDialTimeout      = 30 * time.Second
	sshDetectionTimeout = 5 * time.Second
)

// PasswordRequiredMarker tells Java to prompt for a password and retry. It is
// a string because gomobile flattens errors to their message, so a sentinel
// value would not survive the binding.
const PasswordRequiredMarker = "netbird-ssh-password-required"

// HostKeyUnknownMarker tells Java to show the fingerprint and, on confirmation,
// retry with TrustHostKey set. The presented fingerprint is appended after the
// marker so the prompt can display it and the retry can guard against a key
// that changed between the two connects. Only regular (non-NetBird) servers
// reach this: NetBird peers verify against the registry.
const HostKeyUnknownMarker = "netbird-ssh-hostkey-unknown"

var (
	errPasswordRequired = errors.New(PasswordRequiredMarker)
	errClientClosed     = errors.New("ssh client closed")
)

// errHostKeyUnknown carries the presented fingerprint so Connect can build the
// marker message the Java side parses.
type errHostKeyUnknown struct {
	fingerprint string
}

func (e *errHostKeyUnknown) Error() string {
	return HostKeyUnknownMarker + ":" + e.fingerprint
}

// engineHostKeyVerifier adapts *internal.Engine to nbssh.HostKeyVerifier.
type engineHostKeyVerifier struct {
	engine *internal.Engine
}

func (v *engineHostKeyVerifier) VerifySSHHostKey(peerAddress string, presented []byte) error {
	storedKey, found := v.engine.GetPeerSSHKey(peerAddress)
	if !found {
		return nbssh.ErrPeerNotFound
	}
	return nbssh.VerifyHostKey(storedKey, presented, peerAddress)
}

// SSHTerminalListener receives SSH session events. It is implemented in Java.
//
// All callbacks are invoked from goroutines and may run concurrently with each
// other; the implementation must be safe to call from any thread.
type SSHTerminalListener interface {
	OnConnected()
	OnData(data []byte)
	OnClose(reason string)
	OnError(message string)
}

// SSHClient is a NetBird-aware SSH client exposed to Java via gomobile.
//
// It dials through the running NetBird tunnel and runs a standard SSH session
// on top with PTY enabled. Host-key verification uses the NetBird-provided
// peer SSH host keys, identical to the desktop client.
type SSHClient struct {
	nb        *Client
	mu        sync.Mutex
	listener  SSHTerminalListener
	urlOpener URLOpener

	sshClient *gossh.Client
	session   *gossh.Session
	stdin     io.WriteCloser
	closed    bool

	// gen identifies the current connection attempt. Connect and Close bump it,
	// so an in-flight dial or a reader left over from a previous connection
	// finds itself stale and stays silent instead of publishing OnConnected or
	// OnClose for a connection the caller already abandoned.
	gen        uint64
	dialCancel context.CancelFunc

	// knownHostsPath is the TOFU store for regular SSH servers. Java supplies a
	// per-profile path, since an overlay IP is a different host under a
	// different profile. Empty until set: without it a regular server cannot be
	// verified and Connect refuses one.
	knownHostsPath string
	// trustHostKey carries the fingerprint the user confirmed on a previous
	// attempt, so the retry accepts exactly that key and persists it.
	trustHostKey string
}

// NewSSHClient creates a new SSH client bound to the running NetBird Client.
func NewSSHClient(c *Client) *SSHClient {
	return &SSHClient{nb: c}
}

// SetListener registers the Java listener. Must be called before Connect to
// receive any events.
func (s *SSHClient) SetListener(l SSHTerminalListener) {
	s.mu.Lock()
	s.listener = l
	s.mu.Unlock()
}

// SetURLOpener registers the Java URL opener used to display the device-code
// authorization page in a Custom Tabs window when the target peer requires
// JWT authentication. Must be set before Connect to be effective.
func (s *SSHClient) SetURLOpener(opener URLOpener) {
	s.mu.Lock()
	s.urlOpener = opener
	s.mu.Unlock()
}

// SetKnownHostsPath points the TOFU host-key store at a per-profile file. Must
// be set before connecting to a regular SSH server; without it such a server
// cannot be verified and Connect refuses one.
func (s *SSHClient) SetKnownHostsPath(path string) {
	s.mu.Lock()
	s.knownHostsPath = path
	s.mu.Unlock()
}

// TrustHostKey records the fingerprint the user confirmed for a regular server,
// so the next Connect accepts that exact key and adds it to the known-hosts
// store. Passing a fingerprint that no longer matches makes the connect fail
// rather than trust a key that changed since the prompt.
func (s *SSHClient) TrustHostKey(fingerprint string) {
	s.mu.Lock()
	s.trustHostKey = fingerprint
	s.mu.Unlock()
}

// Connect dials the SSH server through the NetBird tunnel and performs the
// SSH handshake. It auto-detects the server type via SSH banner inspection
// and selects the appropriate authentication path:
//
//   - NetBird-SSH server requiring JWT: launches the OAuth 2.0 device-code
//     flow, opens the verification URL through the registered URLOpener, and
//     uses the resulting token as the SSH password. Host-key verification
//     uses the NetBird peer registry.
//   - NetBird-SSH server without JWT: authenticates with the NetBird SSH
//     private key. Host-key verification uses the NetBird peer registry.
//   - Regular SSH server (e.g. OpenSSH): authenticates with the NetBird key
//     first (so a user-installed NetBird public key works), then falls back
//     to the supplied password if non-empty. Host-key verification is
//     trust-on-first-use against the per-profile known-hosts store.
//
// The password parameter is only consulted for regular SSH servers.
func (s *SSHClient) Connect(host string, port int, user, password string) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid port: %d", port)
	}

	cfg, _, cc := s.nb.stateSnapshot()
	if cc == nil {
		return errors.New("netbird client not running")
	}
	if cfg == nil {
		return errors.New("netbird config not loaded")
	}
	engine := cc.Engine()
	if engine == nil {
		return errors.New("netbird engine not available")
	}

	s.mu.Lock()
	s.gen++
	gen := s.gen
	s.mu.Unlock()

	serverType := detectServerType(host, port)
	log.Debugf("SSH server type: %s", serverType)

	authMethods, hostKeyCallback, err := s.buildAuth(cfg, engine, serverType, password)
	if err != nil {
		return err
	}

	clientConfig := &gossh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         sshDialTimeout,
	}
	err = s.dialAndHandshake(gen, host, port, clientConfig)

	// An unknown host key is a prompt, not a failure: return the marker intact
	// (rootCause would unwrap it) so Java can show the fingerprint and retry.
	var unknownHost *errHostKeyUnknown
	if errors.As(err, &unknownHost) {
		return errors.New(unknownHost.Error())
	}

	// A regular server may still accept a password, so let the caller ask for
	// one instead of failing. NetBird servers never use a password, so a
	// failure there is genuine.
	if err != nil && serverType != detection.ServerTypeNetBirdJWT &&
		serverType != detection.ServerTypeNetBirdNoJWT && isAuthFailure(err) &&
		passwordCouldHelp(err, password != "") {
		return errPasswordRequired
	}
	if err != nil {
		return rootCause(err)
	}
	return nil
}

// isAuthFailure distinguishes credential rejection from dial, timeout and
// host-key errors, which retrying with a password would not fix.
func isAuthFailure(err error) bool {
	if errors.Is(err, errPasswordRequired) {
		return true
	}
	var partial *gossh.PartialSuccessError
	if errors.As(err, &partial) {
		return true
	}
	return strings.Contains(err.Error(), "unable to authenticate")
}

// passwordCouldHelp reports whether prompting for a password again can change
// the outcome. gossh lists a method under "attempted methods" only when the
// server offered it, so a supplied password that was never attempted means the
// server does not accept passwords and the real error should surface instead.
func passwordCouldHelp(err error, passwordOffered bool) bool {
	if !passwordOffered {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "password") || strings.Contains(msg, "keyboard-interactive")
}

// StartSession requests a PTY and starts an interactive shell. Output from
// the session is forwarded to the listener via OnData.
func (s *SSHClient) StartSession(cols, rows int) error {
	err := s.startSession(cols, rows)
	if err != nil {
		log.Infof("SSH: start session failed: %v", err)
		return rootCause(err)
	}
	return nil
}

func (s *SSHClient) startSession(cols, rows int) error {
	log.Debugf("SSH: starting session %dx%d", cols, rows)
	s.mu.Lock()
	sshClient := s.sshClient
	gen := s.gen
	s.mu.Unlock()

	if sshClient == nil {
		return errors.New("ssh client not connected")
	}

	session, err := sshClient.NewSession()
	if err != nil {
		return fmt.Errorf("new session: %w", err)
	}

	modes := gossh.TerminalModes{
		gossh.ECHO:          1,
		gossh.TTY_OP_ISPEED: 14400,
		gossh.TTY_OP_OSPEED: 14400,
		gossh.VINTR:         3,
		gossh.VQUIT:         28,
		gossh.VERASE:        127,
	}
	if err := session.RequestPty("xterm-256color", rows, cols, modes); err != nil {
		closeQuiet(session, "session after pty error")
		return fmt.Errorf("request pty: %w", err)
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		closeQuiet(session, "session after stdin error")
		return fmt.Errorf("stdin pipe: %w", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		closeQuiet(session, "session after stdout error")
		return fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		closeQuiet(session, "session after stderr error")
		return fmt.Errorf("stderr pipe: %w", err)
	}

	if err := session.Shell(); err != nil {
		closeQuiet(session, "session after shell error")
		return fmt.Errorf("start shell: %w", err)
	}

	s.mu.Lock()
	if gen != s.gen {
		s.mu.Unlock()
		closeQuiet(session, "stale session")
		return errClientClosed
	}
	s.session = session
	s.stdin = stdin
	s.mu.Unlock()

	readerDone := make(chan string, 2)
	go func() { readerDone <- s.readLoop(stdout, "stdout") }()
	go func() { readerDone <- s.readLoop(stderr, "stderr") }()
	go func() {
		reason := <-readerDone
		if second := <-readerDone; reason == "" {
			reason = second
		}
		s.notifyClose(gen, reason)
	}()
	log.Debug("SSH: session started, shell running")
	return nil
}

// Write sends data to the SSH session stdin.
func (s *SSHClient) Write(data []byte) error {
	s.mu.Lock()
	stdin := s.stdin
	s.mu.Unlock()
	if stdin == nil {
		return errors.New("ssh session not started")
	}
	if _, err := stdin.Write(data); err != nil {
		return fmt.Errorf("write stdin: %w", err)
	}
	return nil
}

// Resize updates the PTY window size.
func (s *SSHClient) Resize(cols, rows int) error {
	s.mu.Lock()
	session := s.session
	s.mu.Unlock()
	if session == nil {
		return errors.New("ssh session not started")
	}
	return session.WindowChange(rows, cols)
}

// Reset makes a closed client usable for another Connect: Close leaves the
// one-shot guard set, and clearing it lets the same client back a reconnect.
func (s *SSHClient) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = false
}

// Close terminates the SSH session and underlying connection. Safe to call
// multiple times.
func (s *SSHClient) Close() error {
	s.mu.Lock()
	s.gen++
	if s.dialCancel != nil {
		s.dialCancel()
		s.dialCancel = nil
	}
	sshClient := s.sshClient
	session := s.session
	stdin := s.stdin
	s.sshClient = nil
	s.session = nil
	s.stdin = nil
	notify := !s.closed
	s.closed = true
	listener := s.listener
	s.mu.Unlock()

	if stdin != nil {
		if err := stdin.Close(); err != nil {
			log.Debugf("ssh: stdin close: %v", err)
		}
	}
	if session != nil {
		if err := session.Close(); err != nil && !errors.Is(err, io.EOF) {
			log.Debugf("ssh: session close: %v", err)
		}
	}
	var firstErr error
	if sshClient != nil {
		if err := sshClient.Close(); err != nil {
			firstErr = err
		}
	}
	if notify && listener != nil {
		listener.OnClose("closed by client")
	}
	return firstErr
}

func (s *SSHClient) buildAuth(cfg *profilemanager.Config, engine *internal.Engine,
	serverType detection.ServerType, password string) ([]gossh.AuthMethod, gossh.HostKeyCallback, error) {

	switch serverType {
	case detection.ServerTypeNetBirdJWT:
		token, err := s.requestJWTToken(cfg)
		if err != nil {
			return nil, nil, fmt.Errorf("jwt: %w", err)
		}
		auths := []gossh.AuthMethod{gossh.Password(token)}
		return auths, nbssh.CreateHostKeyCallback(&engineHostKeyVerifier{engine: engine}), nil

	case detection.ServerTypeNetBirdNoJWT:
		if cfg.SSHKey == "" {
			return nil, nil, errors.New("no NetBird SSH key available")
		}
		signer, err := gossh.ParsePrivateKey([]byte(cfg.SSHKey))
		if err != nil {
			return nil, nil, fmt.Errorf("parse netbird ssh key: %w", err)
		}
		auths := []gossh.AuthMethod{gossh.PublicKeys(signer)}
		return auths, nbssh.CreateHostKeyCallback(&engineHostKeyVerifier{engine: engine}), nil

	case detection.ServerTypeRegular:
		var auths []gossh.AuthMethod
		if cfg.SSHKey != "" {
			if signer, err := gossh.ParsePrivateKey([]byte(cfg.SSHKey)); err == nil {
				auths = append(auths, gossh.PublicKeys(signer))
			} else {
				log.Debugf("ssh: parse netbird key for regular auth: %v", err)
			}
		}
		if password != "" {
			pw := password
			auths = append(auths, gossh.Password(pw))
			auths = append(auths, gossh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range questions {
					answers[i] = pw
				}
				return answers, nil
			}))
		}
		if len(auths) == 0 {
			// Nothing to offer at all: ask for a password rather than failing,
			// so the caller can retry once the user supplies one.
			return nil, nil, errPasswordRequired
		}
		callback, err := s.tofuHostKeyCallback()
		if err != nil {
			return nil, nil, err
		}
		return auths, callback, nil

	default:
		return nil, nil, fmt.Errorf("unsupported SSH server type: %v", serverType)
	}
}

// tofuHostKeyCallback verifies a regular server's host key against the
// per-profile known-hosts file. An unknown host returns errHostKeyUnknown so
// Java can show the fingerprint and, once confirmed, retry with the key
// trusted; a changed key is rejected outright, as OpenSSH does. When the user
// has confirmed a fingerprint, the callback accepts exactly that key and
// appends it to the store.
func (s *SSHClient) tofuHostKeyCallback() (gossh.HostKeyCallback, error) {
	s.mu.Lock()
	path := s.knownHostsPath
	trusted := s.trustHostKey
	s.mu.Unlock()

	if path == "" {
		return nil, errors.New("no known-hosts store configured for regular SSH")
	}

	if err := ensureFileExists(path); err != nil {
		return nil, fmt.Errorf("prepare known-hosts store: %w", err)
	}

	known, err := knownhosts.New(path)
	if err != nil {
		return nil, fmt.Errorf("load known-hosts store: %w", err)
	}

	return func(hostname string, remote net.Addr, key gossh.PublicKey) error {
		err := known(hostname, remote, key)
		if err == nil {
			return nil
		}

		var keyErr *knownhosts.KeyError
		if !errors.As(err, &keyErr) {
			return err
		}
		// Want holds the keys already stored for this host: non-empty means the
		// presented key replaced a known one, which TOFU must never accept
		// silently.
		if len(keyErr.Want) > 0 {
			return fmt.Errorf("SSH host key changed for %s (possible attack)", hostname)
		}

		fingerprint := gossh.FingerprintSHA256(key)
		if trusted == "" {
			return &errHostKeyUnknown{fingerprint: fingerprint}
		}
		if trusted != fingerprint {
			return fmt.Errorf("SSH host key changed since it was confirmed for %s", hostname)
		}
		if err := appendKnownHost(path, hostname, remote, key); err != nil {
			return fmt.Errorf("persist trusted host key: %w", err)
		}
		// The confirmation is spent: now that the key is stored, a later
		// reconnect must verify against the file, not re-accept this fingerprint.
		s.mu.Lock()
		s.trustHostKey = ""
		s.mu.Unlock()
		return nil
	}, nil
}

func (s *SSHClient) requestJWTToken(cfg *profilemanager.Config) (string, error) {
	s.mu.Lock()
	urlOpener := s.urlOpener
	s.mu.Unlock()
	if urlOpener == nil {
		return "", errors.New("URL opener not configured for JWT auth")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	flow, err := auth.NewOAuthFlow(ctx, cfg, false, true, profilemanager.GetLoginHint())
	if err != nil {
		return "", fmt.Errorf("create oauth flow: %w", err)
	}

	flowInfo, err := flow.RequestAuthInfo(ctx)
	if err != nil {
		return "", fmt.Errorf("request auth info: %w", err)
	}

	// Called synchronously: Open is what marks the surface as opened on the
	// client side, and OnLoginSuccess below is a no-op until it has. Starting
	// both in their own goroutines let them race, so a fast token left the
	// browser in front of the terminal.
	urlOpener.Open(flowInfo.VerificationURIComplete, flowInfo.UserCode)

	// WaitToken blocks for as long as the browser round-trip takes, so say so
	// rather than leaving the terminal blank.
	s.notifyStatus("Waiting for browser authentication...")

	tokenInfo, err := flow.WaitToken(ctx, flowInfo)
	if err != nil {
		return "", fmt.Errorf("wait for token: %w", err)
	}

	token := tokenInfo.GetTokenToUse()
	if token == "" {
		return "", errors.New("empty token returned by IdP")
	}

	// Tells the client the browser round-trip is over so it can dismiss the
	// surface it opened, the same way the login and session-extend flows do.
	// Without it the Custom Tab stays in front of the terminal even though the
	// token has already been collected.
	urlOpener.OnLoginSuccess()

	return token, nil
}

func (s *SSHClient) dialAndHandshake(gen uint64, host string, port int, clientConfig *gossh.ClientConfig) error {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	ctx, cancel := context.WithTimeout(context.Background(), sshDialTimeout)
	defer cancel()

	s.mu.Lock()
	if gen != s.gen {
		s.mu.Unlock()
		return errClientClosed
	}
	s.dialCancel = cancel
	s.mu.Unlock()

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}

	// DialContext bounds only the TCP establishment; without a deadline on the
	// socket a peer that accepts and then goes silent blocks the handshake
	// forever.
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			closeQuiet(conn, "conn after deadline error")
			return fmt.Errorf("set handshake deadline: %w", err)
		}
	}

	sshConn, chans, reqs, err := gossh.NewClientConn(conn, addr, clientConfig)
	if err != nil {
		if cerr := conn.Close(); cerr != nil {
			log.Debugf("ssh: close after handshake error: %v", cerr)
		}
		return fmt.Errorf("ssh handshake: %w", err)
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		closeQuiet(sshConn, "ssh conn after deadline clear error")
		return fmt.Errorf("clear handshake deadline: %w", err)
	}

	client := gossh.NewClient(sshConn, chans, reqs)
	s.mu.Lock()
	if gen != s.gen {
		s.mu.Unlock()
		closeQuiet(client, "stale ssh client")
		return errClientClosed
	}
	s.sshClient = client
	listener := s.listener
	s.mu.Unlock()

	if listener != nil {
		listener.OnConnected()
	}
	return nil
}

func (s *SSHClient) readLoop(r io.Reader, name string) string {
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			s.mu.Lock()
			listener := s.listener
			s.mu.Unlock()
			if listener != nil {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				listener.OnData(chunk)
			}
		}
		if err != nil {
			// EOF is a normal shell exit, so report it without a reason.
			if errors.Is(err, io.EOF) {
				return ""
			}
			log.Debugf("ssh %s read: %v", name, err)
			return rootCause(err).Error()
		}
	}
}

// notifyStatus writes a progress line to the terminal through the normal
// output path, so long steps are visible while nothing else is arriving.
func (s *SSHClient) notifyStatus(text string) {
	s.mu.Lock()
	listener := s.listener
	s.mu.Unlock()
	if listener != nil {
		listener.OnData([]byte("\r\n\x1b[33m" + text + "\x1b[0m\r\n"))
	}
}

func (s *SSHClient) notifyClose(gen uint64, reason string) {
	s.mu.Lock()
	if gen != s.gen || s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	listener := s.listener
	s.mu.Unlock()
	if listener != nil {
		listener.OnClose(reason)
	}
}

func closeQuiet(c io.Closer, label string) {
	if c == nil {
		return
	}
	if err := c.Close(); err != nil && !errors.Is(err, io.EOF) {
		log.Debugf("ssh: close %s: %v", label, err)
	}
}

func detectServerType(host string, port int) detection.ServerType {
	ctx, cancel := context.WithTimeout(context.Background(), sshDetectionTimeout)
	defer cancel()

	dialer := &net.Dialer{}
	serverType, err := detection.DetectSSHServerType(ctx, dialer, host, port)
	if err != nil {
		log.Debugf("ssh: server detection failed: %v (assuming regular SSH)", err)
		return detection.ServerTypeRegular
	}
	return serverType
}

// rootCause returns the innermost error of a %w chain, so the terminal shows
// "i/o timeout" rather than every layer that added context on the way up.
func rootCause(err error) error {
	for {
		// A joined error has no single root, so keep it as-is.
		if _, ok := err.(interface{ Unwrap() []error }); ok {
			return err
		}
		next := errors.Unwrap(err)
		if next == nil {
			return err
		}
		err = next
	}
}

// ensureFileExists creates an empty known-hosts file when none exists yet, so
// knownhosts.New has something to parse on the first connection to any host.
func ensureFileExists(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	return f.Close()
}

// appendKnownHost adds the confirmed key to the store in the standard
// known_hosts format, so it verifies silently on later connections and can be
// inspected or edited like any OpenSSH known_hosts file.
func appendKnownHost(path, hostname string, remote net.Addr, key gossh.PublicKey) error {
	addresses := []string{knownhosts.Normalize(hostname)}
	if remote != nil {
		if normalized := knownhosts.Normalize(remote.String()); normalized != addresses[0] {
			addresses = append(addresses, normalized)
		}
	}
	line := knownhosts.Line(addresses, key)

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			log.Debugf("ssh: close known-hosts after append: %v", cerr)
		}
	}()
	_, err = f.WriteString(line + "\n")
	return err
}

// RemoveKnownHost deletes every known_hosts entry for host:port from the store,
// so a host trusted for a session that is being deleted does not linger. Java
// calls this only once no session targets that host, so a shared host stays
// trusted. Missing file or entry is not an error: the goal state is "absent".
func RemoveKnownHost(path, host string, port int) error {
	target := knownhosts.Normalize(net.JoinHostPort(host, strconv.Itoa(port)))

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var kept []string
	changed := false
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if knownHostsLineMatches(line, target) {
			changed = true
			continue
		}
		kept = append(kept, line)
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if !changed {
		return nil
	}

	out := strings.Join(kept, "\n")
	if len(kept) > 0 {
		out += "\n"
	}
	return os.WriteFile(path, []byte(out), 0o600)
}

// knownHostsLineMatches reports whether a known_hosts line's address list
// contains the normalized target. Comment and blank lines never match.
func knownHostsLineMatches(line, target string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return false
	}
	fields := strings.Fields(trimmed)
	if len(fields) == 0 {
		return false
	}
	for _, addr := range strings.Split(fields[0], ",") {
		if addr == target {
			return true
		}
	}
	return false
}
