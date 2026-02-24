package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gliderlabs/ssh"
	log "github.com/sirupsen/logrus"
	cryptossh "golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
	nbssh "github.com/netbirdio/netbird/client/ssh"
	"github.com/netbirdio/netbird/client/ssh/detection"
	"github.com/netbirdio/netbird/version"
)

const (
	// sshConnectionTimeout is the timeout for SSH TCP connection establishment
	sshConnectionTimeout = 120 * time.Second
	// sshHandshakeTimeout is the timeout for SSH handshake completion
	sshHandshakeTimeout = 30 * time.Second

	jwtAuthErrorMsg = "JWT authentication: %w"
)

type SSHProxy struct {
	daemonAddr    string
	targetHost    string
	targetPort    int
	stderr        io.Writer
	conn          *grpc.ClientConn
	daemonClient  proto.DaemonServiceClient
	browserOpener func(string) error

	mu            sync.RWMutex
	backendClient *cryptossh.Client
	// jwtToken is set once in runProxySSHServer before any handlers are called,
	// so concurrent access is safe without additional synchronization.
	jwtToken string

	forwardedChannelsOnce sync.Once
}

func New(daemonAddr, targetHost string, targetPort int, stderr io.Writer, browserOpener func(string) error) (*SSHProxy, error) {
	grpcAddr := strings.TrimPrefix(daemonAddr, "tcp://")
	grpcConn, err := grpc.NewClient(grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("connect to daemon: %w", err)
	}

	return &SSHProxy{
		daemonAddr:    daemonAddr,
		targetHost:    targetHost,
		targetPort:    targetPort,
		stderr:        stderr,
		conn:          grpcConn,
		daemonClient:  proto.NewDaemonServiceClient(grpcConn),
		browserOpener: browserOpener,
	}, nil
}

func (p *SSHProxy) Close() error {
	p.mu.Lock()
	backendClient := p.backendClient
	p.backendClient = nil
	p.mu.Unlock()

	if backendClient != nil {
		if err := backendClient.Close(); err != nil {
			log.Debugf("close backend client: %v", err)
		}
	}

	if p.conn != nil {
		return p.conn.Close()
	}
	return nil
}

func (p *SSHProxy) Connect(ctx context.Context) error {
	hint := profilemanager.GetLoginHint()

	jwtToken, err := nbssh.RequestJWTToken(ctx, p.daemonClient, nil, p.stderr, true, hint, p.browserOpener)
	if err != nil {
		return fmt.Errorf(jwtAuthErrorMsg, err)
	}

	log.Debugf("JWT authentication successful, starting proxy to %s:%d", p.targetHost, p.targetPort)
	return p.runProxySSHServer(jwtToken)
}

func (p *SSHProxy) runProxySSHServer(jwtToken string) error {
	p.jwtToken = jwtToken
	serverVersion := fmt.Sprintf("%s-%s", detection.ProxyIdentifier, version.NetbirdVersion())

	sshServer := &ssh.Server{
		Handler: p.handleSSHSession,
		ChannelHandlers: map[string]ssh.ChannelHandler{
			"session":      ssh.DefaultSessionHandler,
			"direct-tcpip": p.directTCPIPHandler,
		},
		SubsystemHandlers: map[string]ssh.SubsystemHandler{
			"sftp": func(s ssh.Session) {
				p.sftpSubsystemHandler(s, jwtToken)
			},
		},
		RequestHandlers: map[string]ssh.RequestHandler{
			"tcpip-forward":        p.tcpipForwardHandler,
			"cancel-tcpip-forward": p.cancelTcpipForwardHandler,
		},
		Version: serverVersion,
	}

	hostKey, err := generateHostKey()
	if err != nil {
		return fmt.Errorf("generate host key: %w", err)
	}
	sshServer.HostSigners = []ssh.Signer{hostKey}

	conn := &stdioConn{
		stdin:  os.Stdin,
		stdout: os.Stdout,
	}

	sshServer.HandleConn(conn)

	return nil
}

func (p *SSHProxy) handleSSHSession(session ssh.Session) {
	ptyReq, winCh, isPty := session.Pty()
	hasCommand := len(session.Command()) > 0

	sshClient, err := p.getOrCreateBackendClient(session.Context(), session.User())
	if err != nil {
		_, _ = fmt.Fprintf(p.stderr, "SSH connection to NetBird server failed: %v\n", err)
		return
	}

	if !isPty && !hasCommand {
		p.handleNonInteractiveSession(session, sshClient)
		return
	}

	serverSession, err := sshClient.NewSession()
	if err != nil {
		_, _ = fmt.Fprintf(p.stderr, "create server session: %v\n", err)
		return
	}
	defer func() { _ = serverSession.Close() }()

	serverSession.Stdin = session
	serverSession.Stdout = session
	serverSession.Stderr = session.Stderr()

	if isPty {
		if err := serverSession.RequestPty(ptyReq.Term, ptyReq.Window.Width, ptyReq.Window.Height, nil); err != nil {
			log.Debugf("PTY request to backend: %v", err)
		}

		go func() {
			for win := range winCh {
				if err := serverSession.WindowChange(win.Height, win.Width); err != nil {
					log.Debugf("window change: %v", err)
				}
			}
		}()
	}

	if hasCommand {
		if err := serverSession.Run(strings.Join(session.Command(), " ")); err != nil {
			log.Debugf("run command: %v", err)
			p.handleProxyExitCode(session, err)
		}
		return
	}

	if err = serverSession.Shell(); err != nil {
		log.Debugf("start shell: %v", err)
		return
	}
	if err := serverSession.Wait(); err != nil {
		log.Debugf("session wait: %v", err)
		p.handleProxyExitCode(session, err)
	}
}

func (p *SSHProxy) handleProxyExitCode(session ssh.Session, err error) {
	var exitErr *cryptossh.ExitError
	if errors.As(err, &exitErr) {
		if err := session.Exit(exitErr.ExitStatus()); err != nil {
			log.Debugf("set exit status: %v", err)
		}
	}
}

func (p *SSHProxy) handleNonInteractiveSession(session ssh.Session, sshClient *cryptossh.Client) {
	serverSession, err := sshClient.NewSession()
	if err != nil {
		_, _ = fmt.Fprintf(p.stderr, "create server session: %v\n", err)
		return
	}
	defer func() { _ = serverSession.Close() }()

	serverSession.Stdin = session
	serverSession.Stdout = session
	serverSession.Stderr = session.Stderr()

	if err := serverSession.Shell(); err != nil {
		log.Debugf("start shell: %v", err)
		return
	}

	done := make(chan error, 1)
	go func() {
		done <- serverSession.Wait()
	}()

	select {
	case <-session.Context().Done():
		return
	case err := <-done:
		if err != nil {
			log.Debugf("shell session: %v", err)
			p.handleProxyExitCode(session, err)
		}
	}
}

func generateHostKey() (ssh.Signer, error) {
	keyPEM, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	if err != nil {
		return nil, fmt.Errorf("generate ED25519 key: %w", err)
	}

	signer, err := cryptossh.ParsePrivateKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	return signer, nil
}

type stdioConn struct {
	stdin  io.Reader
	stdout io.Writer
	closed bool
	mu     sync.Mutex
}

func (c *stdioConn) Read(b []byte) (n int, err error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, io.EOF
	}
	c.mu.Unlock()
	return c.stdin.Read(b)
}

func (c *stdioConn) Write(b []byte) (n int, err error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	c.mu.Unlock()
	return c.stdout.Write(b)
}

func (c *stdioConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (c *stdioConn) LocalAddr() net.Addr {
	return &net.UnixAddr{Name: "stdio", Net: "unix"}
}

func (c *stdioConn) RemoteAddr() net.Addr {
	return &net.UnixAddr{Name: "stdio", Net: "unix"}
}

func (c *stdioConn) SetDeadline(_ time.Time) error {
	return nil
}

func (c *stdioConn) SetReadDeadline(_ time.Time) error {
	return nil
}

func (c *stdioConn) SetWriteDeadline(_ time.Time) error {
	return nil
}

// directTCPIPHandler handles local port forwarding (direct-tcpip channel).
func (p *SSHProxy) directTCPIPHandler(_ *ssh.Server, _ *cryptossh.ServerConn, newChan cryptossh.NewChannel, sshCtx ssh.Context) {
	var payload struct {
		DestAddr   string
		DestPort   uint32
		OriginAddr string
		OriginPort uint32
	}
	if err := cryptossh.Unmarshal(newChan.ExtraData(), &payload); err != nil {
		_, _ = fmt.Fprintf(p.stderr, "parse direct-tcpip payload: %v\n", err)
		_ = newChan.Reject(cryptossh.ConnectionFailed, "invalid payload")
		return
	}

	dest := fmt.Sprintf("%s:%d", payload.DestAddr, payload.DestPort)
	log.Debugf("local port forwarding: %s", dest)

	backendClient, err := p.getOrCreateBackendClient(sshCtx, sshCtx.User())
	if err != nil {
		_, _ = fmt.Fprintf(p.stderr, "backend connection for port forwarding: %v\n", err)
		_ = newChan.Reject(cryptossh.ConnectionFailed, "backend connection failed")
		return
	}

	backendChan, backendReqs, err := backendClient.OpenChannel("direct-tcpip", newChan.ExtraData())
	if err != nil {
		_, _ = fmt.Fprintf(p.stderr, "open backend channel for %s: %v\n", dest, err)
		var openErr *cryptossh.OpenChannelError
		if errors.As(err, &openErr) {
			_ = newChan.Reject(openErr.Reason, openErr.Message)
		} else {
			_ = newChan.Reject(cryptossh.ConnectionFailed, err.Error())
		}
		return
	}
	go cryptossh.DiscardRequests(backendReqs)

	clientChan, clientReqs, err := newChan.Accept()
	if err != nil {
		log.Debugf("local port forwarding: accept channel: %v", err)
		_ = backendChan.Close()
		return
	}
	go cryptossh.DiscardRequests(clientReqs)

	nbssh.BidirectionalCopyWithContext(log.NewEntry(log.StandardLogger()), sshCtx, clientChan, backendChan)
}

func (p *SSHProxy) sftpSubsystemHandler(s ssh.Session, jwtToken string) {
	ctx, cancel := context.WithCancel(s.Context())
	defer cancel()

	targetAddr := net.JoinHostPort(p.targetHost, strconv.Itoa(p.targetPort))

	sshClient, err := p.dialBackend(ctx, targetAddr, s.User(), jwtToken)
	if err != nil {
		_, _ = fmt.Fprintf(s, "SSH connection failed: %v\n", err)
		_ = s.Exit(1)
		return
	}
	defer func() {
		if err := sshClient.Close(); err != nil {
			log.Debugf("close SSH client: %v", err)
		}
	}()

	serverSession, err := sshClient.NewSession()
	if err != nil {
		_, _ = fmt.Fprintf(s, "create server session: %v\n", err)
		_ = s.Exit(1)
		return
	}
	defer func() {
		if err := serverSession.Close(); err != nil {
			log.Debugf("close server session: %v", err)
		}
	}()

	stdin, stdout, err := p.setupSFTPPipes(serverSession)
	if err != nil {
		log.Debugf("setup SFTP pipes: %v", err)
		_ = s.Exit(1)
		return
	}

	if err := serverSession.RequestSubsystem("sftp"); err != nil {
		_, _ = fmt.Fprintf(s, "SFTP subsystem request failed: %v\n", err)
		_ = s.Exit(1)
		return
	}

	p.runSFTPBridge(ctx, s, stdin, stdout, serverSession)
}

func (p *SSHProxy) setupSFTPPipes(serverSession *cryptossh.Session) (io.WriteCloser, io.Reader, error) {
	stdin, err := serverSession.StdinPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("get stdin pipe: %w", err)
	}

	stdout, err := serverSession.StdoutPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("get stdout pipe: %w", err)
	}

	return stdin, stdout, nil
}

func (p *SSHProxy) runSFTPBridge(ctx context.Context, s ssh.Session, stdin io.WriteCloser, stdout io.Reader, serverSession *cryptossh.Session) {
	copyErrCh := make(chan error, 2)

	go func() {
		_, err := io.Copy(stdin, s)
		if err != nil {
			log.Debugf("SFTP client to server copy: %v", err)
		}
		if err := stdin.Close(); err != nil {
			log.Debugf("close stdin: %v", err)
		}
		copyErrCh <- err
	}()

	go func() {
		_, err := io.Copy(s, stdout)
		if err != nil {
			log.Debugf("SFTP server to client copy: %v", err)
		}
		copyErrCh <- err
	}()

	go func() {
		<-ctx.Done()
		if err := serverSession.Close(); err != nil {
			log.Debugf("force close server session on context cancellation: %v", err)
		}
	}()

	for i := 0; i < 2; i++ {
		if err := <-copyErrCh; err != nil && !errors.Is(err, io.EOF) {
			log.Debugf("SFTP copy error: %v", err)
		}
	}

	if err := serverSession.Wait(); err != nil {
		log.Debugf("SFTP session ended: %v", err)
	}
}

// tcpipForwardHandler handles remote port forwarding (tcpip-forward request).
func (p *SSHProxy) tcpipForwardHandler(sshCtx ssh.Context, _ *ssh.Server, req *cryptossh.Request) (bool, []byte) {
	var reqPayload struct {
		Host string
		Port uint32
	}
	if err := cryptossh.Unmarshal(req.Payload, &reqPayload); err != nil {
		_, _ = fmt.Fprintf(p.stderr, "parse tcpip-forward payload: %v\n", err)
		return false, nil
	}

	log.Debugf("tcpip-forward request for %s:%d", reqPayload.Host, reqPayload.Port)

	backendClient, err := p.getOrCreateBackendClient(sshCtx, sshCtx.User())
	if err != nil {
		_, _ = fmt.Fprintf(p.stderr, "backend connection for remote port forwarding: %v\n", err)
		return false, nil
	}

	ok, payload, err := backendClient.SendRequest(req.Type, req.WantReply, req.Payload)
	if err != nil {
		_, _ = fmt.Fprintf(p.stderr, "forward tcpip-forward request for %s:%d: %v\n", reqPayload.Host, reqPayload.Port, err)
		return false, nil
	}

	if ok {
		actualPort := reqPayload.Port
		if reqPayload.Port == 0 && len(payload) >= 4 {
			actualPort = binary.BigEndian.Uint32(payload)
		}
		log.Debugf("remote port forwarding established for %s:%d", reqPayload.Host, actualPort)
		p.forwardedChannelsOnce.Do(func() {
			go p.handleForwardedChannels(sshCtx, backendClient)
		})
	}

	return ok, payload
}

// cancelTcpipForwardHandler handles cancel-tcpip-forward request.
func (p *SSHProxy) cancelTcpipForwardHandler(_ ssh.Context, _ *ssh.Server, req *cryptossh.Request) (bool, []byte) {
	var reqPayload struct {
		Host string
		Port uint32
	}
	if err := cryptossh.Unmarshal(req.Payload, &reqPayload); err != nil {
		_, _ = fmt.Fprintf(p.stderr, "parse cancel-tcpip-forward payload: %v\n", err)
		return false, nil
	}

	log.Debugf("cancel-tcpip-forward request for %s:%d", reqPayload.Host, reqPayload.Port)

	backendClient := p.getBackendClient()
	if backendClient == nil {
		return false, nil
	}

	ok, payload, err := backendClient.SendRequest(req.Type, req.WantReply, req.Payload)
	if err != nil {
		_, _ = fmt.Fprintf(p.stderr, "cancel-tcpip-forward for %s:%d: %v\n", reqPayload.Host, reqPayload.Port, err)
		return false, nil
	}

	return ok, payload
}

// getOrCreateBackendClient returns the existing backend client or creates a new one.
func (p *SSHProxy) getOrCreateBackendClient(ctx context.Context, user string) (*cryptossh.Client, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.backendClient != nil {
		return p.backendClient, nil
	}

	targetAddr := net.JoinHostPort(p.targetHost, strconv.Itoa(p.targetPort))
	log.Debugf("connecting to backend %s", targetAddr)

	client, err := p.dialBackend(ctx, targetAddr, user, p.jwtToken)
	if err != nil {
		return nil, err
	}

	log.Debugf("backend connection established to %s", targetAddr)
	p.backendClient = client
	return client, nil
}

// getBackendClient returns the existing backend client or nil.
func (p *SSHProxy) getBackendClient() *cryptossh.Client {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.backendClient
}

// handleForwardedChannels handles forwarded-tcpip channels from the backend for remote port forwarding.
// When the backend receives incoming connections on the forwarded port, it sends them as
// "forwarded-tcpip" channels which we need to proxy to the client.
func (p *SSHProxy) handleForwardedChannels(sshCtx ssh.Context, backendClient *cryptossh.Client) {
	sshConn, ok := sshCtx.Value(ssh.ContextKeyConn).(*cryptossh.ServerConn)
	if !ok || sshConn == nil {
		log.Debugf("no SSH connection in context for forwarded channels")
		return
	}

	channelChan := backendClient.HandleChannelOpen("forwarded-tcpip")
	for {
		select {
		case <-sshCtx.Done():
			return
		case newChannel, ok := <-channelChan:
			if !ok {
				return
			}
			go p.handleForwardedChannel(sshCtx, sshConn, newChannel)
		}
	}
}

// handleForwardedChannel handles a single forwarded-tcpip channel from the backend.
func (p *SSHProxy) handleForwardedChannel(sshCtx ssh.Context, sshConn *cryptossh.ServerConn, newChannel cryptossh.NewChannel) {
	backendChan, backendReqs, err := newChannel.Accept()
	if err != nil {
		log.Debugf("remote port forwarding: accept from backend: %v", err)
		return
	}
	go cryptossh.DiscardRequests(backendReqs)

	clientChan, clientReqs, err := sshConn.OpenChannel("forwarded-tcpip", newChannel.ExtraData())
	if err != nil {
		log.Debugf("remote port forwarding: open to client: %v", err)
		_ = backendChan.Close()
		return
	}
	go cryptossh.DiscardRequests(clientReqs)

	nbssh.BidirectionalCopyWithContext(log.NewEntry(log.StandardLogger()), sshCtx, clientChan, backendChan)
}

func (p *SSHProxy) dialBackend(ctx context.Context, addr, user, jwtToken string) (*cryptossh.Client, error) {
	config := &cryptossh.ClientConfig{
		User:            user,
		Auth:            []cryptossh.AuthMethod{cryptossh.Password(jwtToken)},
		Timeout:         sshHandshakeTimeout,
		HostKeyCallback: p.verifyHostKey,
	}

	dialer := &net.Dialer{
		Timeout: sshConnectionTimeout,
	}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connect to server: %w", err)
	}

	clientConn, chans, reqs, err := cryptossh.NewClientConn(conn, addr, config)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("SSH handshake: %w", err)
	}

	return cryptossh.NewClient(clientConn, chans, reqs), nil
}

func (p *SSHProxy) verifyHostKey(hostname string, remote net.Addr, key cryptossh.PublicKey) error {
	verifier := nbssh.NewDaemonHostKeyVerifier(p.daemonClient)
	callback := nbssh.CreateHostKeyCallback(verifier)
	return callback(hostname, remote, key)
}
