package proxy

import (
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

	return p.runProxySSHServer(ctx, jwtToken)
}

func (p *SSHProxy) runProxySSHServer(ctx context.Context, jwtToken string) error {
	serverVersion := fmt.Sprintf("%s-%s", detection.ProxyIdentifier, version.NetbirdVersion())

	sshServer := &ssh.Server{
		Handler: func(s ssh.Session) {
			p.handleSSHSession(ctx, s, jwtToken)
		},
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

func (p *SSHProxy) handleSSHSession(ctx context.Context, session ssh.Session, jwtToken string) {
	targetAddr := net.JoinHostPort(p.targetHost, strconv.Itoa(p.targetPort))

	sshClient, err := p.dialBackend(ctx, targetAddr, session.User(), jwtToken)
	if err != nil {
		_, _ = fmt.Fprintf(p.stderr, "SSH connection to NetBird server failed: %v\n", err)
		return
	}
	defer func() { _ = sshClient.Close() }()

	serverSession, err := sshClient.NewSession()
	if err != nil {
		_, _ = fmt.Fprintf(p.stderr, "create server session: %v\n", err)
		return
	}
	defer func() { _ = serverSession.Close() }()

	serverSession.Stdin = session
	serverSession.Stdout = session
	serverSession.Stderr = session.Stderr()

	ptyReq, winCh, isPty := session.Pty()
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

	if len(session.Command()) > 0 {
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
		if exitErr := session.Exit(exitErr.ExitStatus()); exitErr != nil {
			log.Debugf("set exit status: %v", exitErr)
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

func (p *SSHProxy) directTCPIPHandler(_ *ssh.Server, _ *cryptossh.ServerConn, newChan cryptossh.NewChannel, _ ssh.Context) {
	_ = newChan.Reject(cryptossh.Prohibited, "port forwarding not supported in proxy")
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

func (p *SSHProxy) tcpipForwardHandler(_ ssh.Context, _ *ssh.Server, _ *cryptossh.Request) (bool, []byte) {
	return false, []byte("port forwarding not supported in proxy")
}

func (p *SSHProxy) cancelTcpipForwardHandler(_ ssh.Context, _ *ssh.Server, _ *cryptossh.Request) (bool, []byte) {
	return true, nil
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
