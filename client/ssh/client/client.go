package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
	nbssh "github.com/netbirdio/netbird/client/ssh"
	"github.com/netbirdio/netbird/client/ssh/detection"
)

const (
	// DefaultDaemonAddr is the default address for the NetBird daemon
	DefaultDaemonAddr = "unix:///var/run/netbird.sock"
	// DefaultDaemonAddrWindows is the default address for the NetBird daemon on Windows
	DefaultDaemonAddrWindows = "tcp://127.0.0.1:41731"
)

// Client wraps crypto/ssh Client for simplified SSH operations
type Client struct {
	client        *ssh.Client
	terminalState *term.State
	terminalFd    int

	windowsStdoutMode uint32 // nolint:unused
	windowsStdinMode  uint32 // nolint:unused
}

func (c *Client) Close() error {
	return c.client.Close()
}

func (c *Client) OpenTerminal(ctx context.Context) error {
	session, err := c.client.NewSession()
	if err != nil {
		return fmt.Errorf("new session: %w", err)
	}
	defer func() {
		if err := session.Close(); err != nil {
			log.Debugf("session close error: %v", err)
		}
	}()

	if err := c.setupTerminalMode(ctx, session); err != nil {
		return err
	}

	c.setupSessionIO(session)

	if err := session.Shell(); err != nil {
		return fmt.Errorf("start shell: %w", err)
	}

	return c.waitForSession(ctx, session)
}

// setupSessionIO connects session streams to local terminal
func (c *Client) setupSessionIO(session *ssh.Session) {
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	session.Stdin = os.Stdin
}

// waitForSession waits for the session to complete with context cancellation
func (c *Client) waitForSession(ctx context.Context, session *ssh.Session) error {
	done := make(chan error, 1)
	go func() {
		done <- session.Wait()
	}()

	defer c.restoreTerminal()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return c.handleSessionError(err)
	}
}

// handleSessionError processes session termination errors
func (c *Client) handleSessionError(err error) error {
	if err == nil {
		return nil
	}

	var e *ssh.ExitError
	var em *ssh.ExitMissingError
	if !errors.As(err, &e) && !errors.As(err, &em) {
		return fmt.Errorf("session wait: %w", err)
	}

	return nil
}

// restoreTerminal restores the terminal to its original state
func (c *Client) restoreTerminal() {
	if c.terminalState != nil {
		_ = term.Restore(c.terminalFd, c.terminalState)
		c.terminalState = nil
		c.terminalFd = 0
	}

	if err := c.restoreWindowsConsoleState(); err != nil {
		log.Debugf("restore Windows console state: %v", err)
	}
}

// ExecuteCommand executes a command on the remote host and returns the output
func (c *Client) ExecuteCommand(ctx context.Context, command string) ([]byte, error) {
	session, cleanup, err := c.createSession(ctx)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	output, err := session.CombinedOutput(command)
	if err != nil {
		var e *ssh.ExitError
		var em *ssh.ExitMissingError
		if !errors.As(err, &e) && !errors.As(err, &em) {
			return output, fmt.Errorf("execute command: %w", err)
		}
	}

	return output, nil
}

// ExecuteCommandWithIO executes a command with interactive I/O connected to local terminal
func (c *Client) ExecuteCommandWithIO(ctx context.Context, command string) error {
	session, cleanup, err := c.createSession(ctx)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	defer cleanup()

	c.setupSessionIO(session)

	if err := session.Start(command); err != nil {
		return fmt.Errorf("start command: %w", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- session.Wait()
	}()

	select {
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGTERM)
		select {
		case <-done:
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
			return ctx.Err()
		}
	case err := <-done:
		return c.handleCommandError(err)
	}
}

// ExecuteCommandWithPTY executes a command with a pseudo-terminal for interactive sessions
func (c *Client) ExecuteCommandWithPTY(ctx context.Context, command string) error {
	session, cleanup, err := c.createSession(ctx)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	defer cleanup()

	if err := c.setupTerminalMode(ctx, session); err != nil {
		return fmt.Errorf("setup terminal mode: %w", err)
	}

	c.setupSessionIO(session)

	if err := session.Start(command); err != nil {
		return fmt.Errorf("start command: %w", err)
	}

	defer c.restoreTerminal()

	done := make(chan error, 1)
	go func() {
		done <- session.Wait()
	}()

	select {
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGTERM)
		select {
		case <-done:
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
			return ctx.Err()
		}
	case err := <-done:
		return c.handleCommandError(err)
	}
}

// handleCommandError processes command execution errors
func (c *Client) handleCommandError(err error) error {
	if err == nil {
		return nil
	}

	var e *ssh.ExitError
	var em *ssh.ExitMissingError
	if errors.As(err, &e) || errors.As(err, &em) {
		return err
	}

	return fmt.Errorf("execute command: %w", err)
}

// setupContextCancellation sets up context cancellation for a session
func (c *Client) setupContextCancellation(ctx context.Context, session *ssh.Session) func() {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = session.Signal(ssh.SIGTERM)
			_ = session.Close()
		case <-done:
		}
	}()
	return func() { close(done) }
}

// createSession creates a new SSH session with context cancellation setup
func (c *Client) createSession(ctx context.Context) (*ssh.Session, func(), error) {
	session, err := c.client.NewSession()
	if err != nil {
		return nil, nil, fmt.Errorf("new session: %w", err)
	}

	cancel := c.setupContextCancellation(ctx, session)
	cleanup := func() {
		cancel()
		_ = session.Close()
	}

	return session, cleanup, nil
}

// getDefaultDaemonAddr returns the daemon address from environment or default for the OS
func getDefaultDaemonAddr() string {
	if addr := os.Getenv("NB_DAEMON_ADDR"); addr != "" {
		return addr
	}
	if runtime.GOOS == "windows" {
		return DefaultDaemonAddrWindows
	}
	return DefaultDaemonAddr
}

// DialOptions contains options for SSH connections
type DialOptions struct {
	KnownHostsFile     string
	IdentityFile       string
	DaemonAddr         string
	SkipCachedToken    bool
	InsecureSkipVerify bool
}

// Dial connects to the given ssh server with specified options
func Dial(ctx context.Context, addr, user string, opts DialOptions) (*Client, error) {
	daemonAddr := opts.DaemonAddr
	if daemonAddr == "" {
		daemonAddr = getDefaultDaemonAddr()
	}
	opts.DaemonAddr = daemonAddr

	hostKeyCallback, err := createHostKeyCallback(opts)
	if err != nil {
		return nil, fmt.Errorf("create host key callback: %w", err)
	}

	config := &ssh.ClientConfig{
		User:            user,
		Timeout:         30 * time.Second,
		HostKeyCallback: hostKeyCallback,
	}

	if opts.IdentityFile != "" {
		authMethod, err := createSSHKeyAuth(opts.IdentityFile)
		if err != nil {
			return nil, fmt.Errorf("create SSH key auth: %w", err)
		}
		config.Auth = append(config.Auth, authMethod)
	}

	return dialWithJWT(ctx, "tcp", addr, config, daemonAddr, opts.SkipCachedToken)
}

// dialSSH establishes an SSH connection without JWT authentication
func dialSSH(ctx context.Context, network, addr string, config *ssh.ClientConfig) (*Client, error) {
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	clientConn, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		if closeErr := conn.Close(); closeErr != nil {
			log.Debugf("connection close after handshake failure: %v", closeErr)
		}
		return nil, fmt.Errorf("ssh handshake: %w", err)
	}

	client := ssh.NewClient(clientConn, chans, reqs)
	return &Client{
		client: client,
	}, nil
}

// dialWithJWT establishes an SSH connection with optional JWT authentication based on server detection
func dialWithJWT(ctx context.Context, network, addr string, config *ssh.ClientConfig, daemonAddr string, skipCache bool) (*Client, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("parse address %s: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("parse port %s: %w", portStr, err)
	}

	detectionCtx, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()

	dialer := &net.Dialer{}
	serverType, err := detection.DetectSSHServerType(detectionCtx, dialer, host, port)
	if err != nil {
		return nil, fmt.Errorf("SSH server detection: %w", err)
	}

	if !serverType.RequiresJWT() {
		return dialSSH(ctx, network, addr, config)
	}

	jwtCtx, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()

	jwtToken, err := requestJWTToken(jwtCtx, daemonAddr, skipCache)
	if err != nil {
		return nil, fmt.Errorf("request JWT token: %w", err)
	}

	configWithJWT := nbssh.AddJWTAuth(config, jwtToken)
	return dialSSH(ctx, network, addr, configWithJWT)
}

// requestJWTToken requests a JWT token from the NetBird daemon
func requestJWTToken(ctx context.Context, daemonAddr string, skipCache bool) (string, error) {
	hint := profilemanager.GetLoginHint()

	conn, err := connectToDaemon(daemonAddr)
	if err != nil {
		return "", fmt.Errorf("connect to daemon: %w", err)
	}
	defer conn.Close()

	client := proto.NewDaemonServiceClient(conn)
	return nbssh.RequestJWTToken(ctx, client, os.Stdout, os.Stderr, !skipCache, hint)
}

// verifyHostKeyViaDaemon verifies SSH host key by querying the NetBird daemon
func verifyHostKeyViaDaemon(hostname string, remote net.Addr, key ssh.PublicKey, daemonAddr string) error {
	conn, err := connectToDaemon(daemonAddr)
	if err != nil {
		return err
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.Debugf("daemon connection close error: %v", err)
		}
	}()

	client := proto.NewDaemonServiceClient(conn)
	verifier := nbssh.NewDaemonHostKeyVerifier(client)
	callback := nbssh.CreateHostKeyCallback(verifier)
	return callback(hostname, remote, key)
}

func connectToDaemon(daemonAddr string) (*grpc.ClientConn, error) {
	addr := strings.TrimPrefix(daemonAddr, "tcp://")

	conn, err := grpc.NewClient(
		addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Debugf("failed to create gRPC client for NetBird daemon at %s: %v", daemonAddr, err)
		return nil, fmt.Errorf("failed to connect to NetBird daemon: %w", err)
	}

	return conn, nil
}

// getKnownHostsFiles returns paths to known_hosts files in order of preference
func getKnownHostsFiles() []string {
	var files []string

	// User's known_hosts file (highest priority)
	if homeDir, err := os.UserHomeDir(); err == nil {
		userKnownHosts := filepath.Join(homeDir, ".ssh", "known_hosts")
		files = append(files, userKnownHosts)
	}

	// NetBird managed known_hosts files
	if runtime.GOOS == "windows" {
		programData := os.Getenv("PROGRAMDATA")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		netbirdKnownHosts := filepath.Join(programData, "ssh", "ssh_known_hosts.d", "99-netbird")
		files = append(files, netbirdKnownHosts)
	} else {
		files = append(files, "/etc/ssh/ssh_known_hosts.d/99-netbird")
		files = append(files, "/etc/ssh/ssh_known_hosts")
	}

	return files
}

// createHostKeyCallback creates a host key verification callback
func createHostKeyCallback(opts DialOptions) (ssh.HostKeyCallback, error) {
	if opts.InsecureSkipVerify {
		return ssh.InsecureIgnoreHostKey(), nil // #nosec G106 - User explicitly requested insecure mode
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if err := tryDaemonVerification(hostname, remote, key, opts.DaemonAddr); err == nil {
			return nil
		}
		return tryKnownHostsVerification(hostname, remote, key, opts.KnownHostsFile)
	}, nil
}

func tryDaemonVerification(hostname string, remote net.Addr, key ssh.PublicKey, daemonAddr string) error {
	if daemonAddr == "" {
		return fmt.Errorf("no daemon address")
	}
	return verifyHostKeyViaDaemon(hostname, remote, key, daemonAddr)
}

func tryKnownHostsVerification(hostname string, remote net.Addr, key ssh.PublicKey, knownHostsFile string) error {
	knownHostsFiles := getKnownHostsFilesList(knownHostsFile)
	hostKeyCallbacks := buildHostKeyCallbacks(knownHostsFiles)

	for _, callback := range hostKeyCallbacks {
		if err := callback(hostname, remote, key); err == nil {
			return nil
		}
	}
	return fmt.Errorf("host key verification failed: key for %s not found in any known_hosts file", hostname)
}

func getKnownHostsFilesList(knownHostsFile string) []string {
	if knownHostsFile != "" {
		return []string{knownHostsFile}
	}
	return getKnownHostsFiles()
}

func buildHostKeyCallbacks(knownHostsFiles []string) []ssh.HostKeyCallback {
	var hostKeyCallbacks []ssh.HostKeyCallback
	for _, file := range knownHostsFiles {
		if callback, err := knownhosts.New(file); err == nil {
			hostKeyCallbacks = append(hostKeyCallbacks, callback)
		}
	}
	return hostKeyCallbacks
}

// createSSHKeyAuth creates SSH key authentication from a private key file
func createSSHKeyAuth(keyFile string) (ssh.AuthMethod, error) {
	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("read SSH key file %s: %w", keyFile, err)
	}

	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("parse SSH private key: %w", err)
	}

	return ssh.PublicKeys(signer), nil
}

// LocalPortForward sets up local port forwarding, binding to localAddr and forwarding to remoteAddr
func (c *Client) LocalPortForward(ctx context.Context, localAddr, remoteAddr string) error {
	localListener, err := net.Listen("tcp", localAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", localAddr, err)
	}

	go func() {
		defer func() {
			if err := localListener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				log.Debugf("local listener close error: %v", err)
			}
		}()
		for {
			localConn, err := localListener.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}

			go c.handleLocalForward(localConn, remoteAddr)
		}
	}()

	<-ctx.Done()
	if err := localListener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Debugf("local listener close error: %v", err)
	}
	return ctx.Err()
}

// handleLocalForward handles a single local port forwarding connection
func (c *Client) handleLocalForward(localConn net.Conn, remoteAddr string) {
	defer func() {
		if err := localConn.Close(); err != nil {
			log.Debugf("local connection close error: %v", err)
		}
	}()

	channel, err := c.client.Dial("tcp", remoteAddr)
	if err != nil {
		if strings.Contains(err.Error(), "administratively prohibited") {
			_, _ = fmt.Fprintf(os.Stderr, "channel open failed: administratively prohibited: port forwarding is disabled\n")
		} else {
			log.Debugf("local port forwarding to %s failed: %v", remoteAddr, err)
		}
		return
	}
	defer func() {
		if err := channel.Close(); err != nil {
			log.Debugf("remote channel close error: %v", err)
		}
	}()

	go func() {
		if _, err := io.Copy(channel, localConn); err != nil {
			log.Debugf("local forward copy error (local->remote): %v", err)
		}
	}()

	if _, err := io.Copy(localConn, channel); err != nil {
		log.Debugf("local forward copy error (remote->local): %v", err)
	}
}

// RemotePortForward sets up remote port forwarding, binding on remote and forwarding to localAddr
func (c *Client) RemotePortForward(ctx context.Context, remoteAddr, localAddr string) error {
	host, port, err := c.parseRemoteAddress(remoteAddr)
	if err != nil {
		return fmt.Errorf("parse remote address: %w", err)
	}

	req := c.buildTCPIPForwardRequest(host, port)
	if err := c.sendTCPIPForwardRequest(req); err != nil {
		return fmt.Errorf("setup remote forward: %w", err)
	}

	go c.handleRemoteForwardChannels(ctx, localAddr)

	<-ctx.Done()

	if err := c.cancelTCPIPForwardRequest(req); err != nil {
		return fmt.Errorf("cancel tcpip-forward: %w", err)
	}
	return ctx.Err()
}

// parseRemoteAddress parses host and port from remote address string
func (c *Client) parseRemoteAddress(remoteAddr string) (string, uint32, error) {
	host, portStr, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return "", 0, fmt.Errorf("parse remote address %s: %w", remoteAddr, err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("parse remote port %s: %w", portStr, err)
	}

	return host, uint32(port), nil
}

// buildTCPIPForwardRequest creates a tcpip-forward request message
func (c *Client) buildTCPIPForwardRequest(host string, port uint32) tcpipForwardMsg {
	return tcpipForwardMsg{
		Host: host,
		Port: port,
	}
}

// sendTCPIPForwardRequest sends the tcpip-forward request to establish remote port forwarding
func (c *Client) sendTCPIPForwardRequest(req tcpipForwardMsg) error {
	ok, _, err := c.client.SendRequest("tcpip-forward", true, ssh.Marshal(&req))
	if err != nil {
		return fmt.Errorf("send tcpip-forward request: %w", err)
	}
	if !ok {
		return fmt.Errorf("remote port forwarding denied by server (check if --allow-ssh-remote-port-forwarding is enabled)")
	}
	return nil
}

// cancelTCPIPForwardRequest cancels the tcpip-forward request
func (c *Client) cancelTCPIPForwardRequest(req tcpipForwardMsg) error {
	_, _, err := c.client.SendRequest("cancel-tcpip-forward", true, ssh.Marshal(&req))
	if err != nil {
		return fmt.Errorf("send cancel-tcpip-forward request: %w", err)
	}
	return nil
}

// handleRemoteForwardChannels handles incoming forwarded-tcpip channels
func (c *Client) handleRemoteForwardChannels(ctx context.Context, localAddr string) {
	// Get the channel once - subsequent calls return nil!
	channelRequests := c.client.HandleChannelOpen("forwarded-tcpip")
	if channelRequests == nil {
		log.Debugf("forwarded-tcpip channel type already being handled")
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case newChan := <-channelRequests:
			if newChan != nil {
				go c.handleRemoteForwardChannel(newChan, localAddr)
			}
		}
	}
}

// handleRemoteForwardChannel handles a single forwarded-tcpip channel
func (c *Client) handleRemoteForwardChannel(newChan ssh.NewChannel, localAddr string) {
	channel, reqs, err := newChan.Accept()
	if err != nil {
		return
	}
	defer func() {
		if err := channel.Close(); err != nil {
			log.Debugf("remote channel close error: %v", err)
		}
	}()

	go ssh.DiscardRequests(reqs)

	localConn, err := net.Dial("tcp", localAddr)
	if err != nil {
		return
	}
	defer func() {
		if err := localConn.Close(); err != nil {
			log.Debugf("local connection close error: %v", err)
		}
	}()

	go func() {
		if _, err := io.Copy(localConn, channel); err != nil {
			log.Debugf("remote forward copy error (remote->local): %v", err)
		}
	}()

	if _, err := io.Copy(channel, localConn); err != nil {
		log.Debugf("remote forward copy error (local->remote): %v", err)
	}
}

// tcpipForwardMsg represents the structure for tcpip-forward requests
type tcpipForwardMsg struct {
	Host string
	Port uint32
}
