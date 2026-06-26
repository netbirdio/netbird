//go:build ios

package NetBirdSDK

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	gossh "golang.org/x/crypto/ssh"

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

// SSHTerminalListener receives SSH session events. It is implemented in Swift.
//
// All callbacks are invoked from goroutines and may run concurrently with each
// other; the implementation must be safe to call from any thread.
type SSHTerminalListener interface {
	OnConnected()
	OnData(data []byte)
	OnClose(reason string)
	OnError(message string)
}

// SSHClient is a NetBird-aware SSH client exposed to Swift via gomobile.
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
}

// NewSSHClient creates a new SSH client bound to the running NetBird Client.
func NewSSHClient(c *Client) *SSHClient {
	return &SSHClient{nb: c}
}

// SetListener registers the Swift listener. Must be called before Connect to
// receive any events.
func (s *SSHClient) SetListener(l SSHTerminalListener) {
	s.mu.Lock()
	s.listener = l
	s.mu.Unlock()
}

// SetURLOpener registers the Swift URL opener used to display the device-code
// authorization page in an in-app browser when the target peer requires JWT
// authentication. Must be set before Connect to be effective.
func (s *SSHClient) SetURLOpener(opener URLOpener) {
	s.mu.Lock()
	s.urlOpener = opener
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
//     disabled (TOFU pending).
//
// The password parameter is only consulted for regular SSH servers.
func (s *SSHClient) Connect(host string, port int, user, password string) error {
	cfg, cc := s.nb.sshState()
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

	serverType := detectServerType(host, port)
	log.Infof("SSH server type for %s:%d: %s", host, port, serverType)

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
	return s.dialAndHandshake(host, port, clientConfig)
}

// StartSession requests a PTY and starts an interactive shell. Output from
// the session is forwarded to the listener via OnData.
func (s *SSHClient) StartSession(cols, rows int) error {
	log.Debugf("SSH: starting session %dx%d", cols, rows)
	s.mu.Lock()
	sshClient := s.sshClient
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
	s.session = session
	s.stdin = stdin
	s.mu.Unlock()

	go s.readLoop(stdout, "stdout")
	go s.readLoop(stderr, "stderr")
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

// Close terminates the SSH session and underlying connection. Safe to call
// multiple times.
func (s *SSHClient) Close() error {
	s.mu.Lock()
	sshClient := s.sshClient
	session := s.session
	stdin := s.stdin
	s.sshClient = nil
	s.session = nil
	s.stdin = nil
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
	s.notifyClose("closed by client")
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

	default: // regular SSH
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
			return nil, nil, errors.New("no auth method available: provide a password or configure NetBird SSH key")
		}
		return auths, gossh.InsecureIgnoreHostKey(), nil // nolint:gosec // TOFU not yet implemented
	}
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

	go urlOpener.Open(flowInfo.VerificationURIComplete, flowInfo.UserCode)

	tokenInfo, err := flow.WaitToken(ctx, flowInfo)
	if err != nil {
		return "", fmt.Errorf("wait for token: %w", err)
	}

	token := tokenInfo.GetTokenToUse()
	if token == "" {
		return "", errors.New("empty token returned by IdP")
	}
	return token, nil
}

func (s *SSHClient) dialAndHandshake(host string, port int, clientConfig *gossh.ClientConfig) error {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	log.Infof("SSH: connecting to %s as %s", addr, clientConfig.User)

	ctx, cancel := context.WithTimeout(context.Background(), sshDialTimeout)
	defer cancel()

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}

	sshConn, chans, reqs, err := gossh.NewClientConn(conn, addr, clientConfig)
	if err != nil {
		if cerr := conn.Close(); cerr != nil {
			log.Debugf("ssh: close after handshake error: %v", cerr)
		}
		return fmt.Errorf("ssh handshake: %w", err)
	}

	s.mu.Lock()
	s.sshClient = gossh.NewClient(sshConn, chans, reqs)
	listener := s.listener
	s.mu.Unlock()

	log.Infof("SSH: connected to %s", addr)
	if listener != nil {
		listener.OnConnected()
	}
	return nil
}

func (s *SSHClient) readLoop(r io.Reader, name string) {
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
			if !errors.Is(err, io.EOF) {
				log.Debugf("ssh %s read: %v", name, err)
			}
			s.notifyClose(err.Error())
			return
		}
	}
}

func (s *SSHClient) notifyClose(reason string) {
	s.mu.Lock()
	if s.closed {
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

func detectServerType(host string, port int) detection.ServerType {
	ctx, cancel := context.WithTimeout(context.Background(), sshDetectionTimeout)
	defer cancel()

	dialer := &net.Dialer{}
	serverType, err := detection.DetectSSHServerType(ctx, dialer, host, port)
	if err != nil {
		log.Debugf("ssh: server detection for %s:%d failed: %v (assuming regular SSH)", host, port, err)
		return detection.ServerTypeRegular
	}
	return serverType
}

func closeQuiet(c io.Closer, label string) {
	if c == nil {
		return
	}
	if err := c.Close(); err != nil && !errors.Is(err, io.EOF) {
		log.Debugf("ssh: close %s: %v", label, err)
	}
}
