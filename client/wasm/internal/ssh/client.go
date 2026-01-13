//go:build js

package ssh

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"

	netbird "github.com/netbirdio/netbird/client/embed"
	nbssh "github.com/netbirdio/netbird/client/ssh"
)

const (
	sshDialTimeout = 30 * time.Second
)

func closeWithLog(c io.Closer, resource string) {
	if c != nil {
		if err := c.Close(); err != nil {
			logrus.Debugf("Failed to close %s: %v", resource, err)
		}
	}
}

type Client struct {
	nbClient  *netbird.Client
	sshClient *ssh.Client
	session   *ssh.Session
	stdin     io.WriteCloser
	stdout    io.Reader
	stderr    io.Reader
	mu        sync.RWMutex
}

// NewClient creates a new SSH client
func NewClient(nbClient *netbird.Client) *Client {
	return &Client{
		nbClient: nbClient,
	}
}

// Connect establishes an SSH connection through NetBird network
func (c *Client) Connect(host string, port int, username, jwtToken string) error {
	addr := fmt.Sprintf("%s:%d", host, port)
	logrus.Infof("SSH: Connecting to %s as %s", addr, username)

	authMethods, err := c.getAuthMethods(jwtToken)
	if err != nil {
		return err
	}

	config := &ssh.ClientConfig{
		User:            username,
		Auth:            authMethods,
		HostKeyCallback: nbssh.CreateHostKeyCallback(c.nbClient),
		Timeout:         sshDialTimeout,
	}

	ctx, cancel := context.WithTimeout(context.Background(), sshDialTimeout)
	defer cancel()

	conn, err := c.nbClient.Dial(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		closeWithLog(conn, "connection after handshake error")
		return fmt.Errorf("SSH handshake: %w", err)
	}

	c.sshClient = ssh.NewClient(sshConn, chans, reqs)
	logrus.Infof("SSH: Connected to %s", addr)

	return nil
}

// getAuthMethods returns SSH authentication methods, preferring JWT if available
func (c *Client) getAuthMethods(jwtToken string) ([]ssh.AuthMethod, error) {
	if jwtToken != "" {
		logrus.Debugf("SSH: Using JWT password authentication")
		return []ssh.AuthMethod{ssh.Password(jwtToken)}, nil
	}

	logrus.Debugf("SSH: No JWT token, using public key authentication")

	nbConfig, err := c.nbClient.GetConfig()
	if err != nil {
		return nil, fmt.Errorf("get NetBird config: %w", err)
	}

	if nbConfig.SSHKey == "" {
		return nil, fmt.Errorf("no NetBird SSH key available")
	}

	signer, err := ssh.ParsePrivateKey([]byte(nbConfig.SSHKey))
	if err != nil {
		return nil, fmt.Errorf("parse NetBird SSH private key: %w", err)
	}

	logrus.Debugf("SSH: Added public key auth")
	return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil
}

// StartSession starts an SSH session with PTY
func (c *Client) StartSession(cols, rows int) error {
	if c.sshClient == nil {
		return fmt.Errorf("SSH client not connected")
	}

	session, err := c.sshClient.NewSession()
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.session = session

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
		ssh.VINTR:         3,
		ssh.VQUIT:         28,
		ssh.VERASE:        127,
	}

	if err := session.RequestPty("xterm-256color", rows, cols, modes); err != nil {
		closeWithLog(session, "session after PTY error")
		return fmt.Errorf("PTY request: %w", err)
	}

	c.stdin, err = session.StdinPipe()
	if err != nil {
		closeWithLog(session, "session after stdin error")
		return fmt.Errorf("get stdin: %w", err)
	}

	c.stdout, err = session.StdoutPipe()
	if err != nil {
		closeWithLog(session, "session after stdout error")
		return fmt.Errorf("get stdout: %w", err)
	}

	c.stderr, err = session.StderrPipe()
	if err != nil {
		closeWithLog(session, "session after stderr error")
		return fmt.Errorf("get stderr: %w", err)
	}

	if err := session.Shell(); err != nil {
		closeWithLog(session, "session after shell error")
		return fmt.Errorf("start shell: %w", err)
	}

	logrus.Info("SSH: Session started with PTY")
	return nil
}

// Write sends data to the SSH session
func (c *Client) Write(data []byte) (int, error) {
	c.mu.RLock()
	stdin := c.stdin
	c.mu.RUnlock()

	if stdin == nil {
		return 0, fmt.Errorf("SSH session not started")
	}
	return stdin.Write(data)
}

// Read reads data from the SSH session
func (c *Client) Read(buffer []byte) (int, error) {
	c.mu.RLock()
	stdout := c.stdout
	c.mu.RUnlock()

	if stdout == nil {
		return 0, fmt.Errorf("SSH session not started")
	}
	return stdout.Read(buffer)
}

// Resize updates the terminal size
func (c *Client) Resize(cols, rows int) error {
	c.mu.RLock()
	session := c.session
	c.mu.RUnlock()

	if session == nil {
		return fmt.Errorf("SSH session not started")
	}
	return session.WindowChange(rows, cols)
}

// Close closes the SSH connection
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.session != nil {
		closeWithLog(c.session, "SSH session")
		c.session = nil
	}
	if c.stdin != nil {
		closeWithLog(c.stdin, "stdin")
		c.stdin = nil
	}
	c.stdout = nil
	c.stderr = nil

	if c.sshClient != nil {
		err := c.sshClient.Close()
		c.sshClient = nil
		return err
	}
	return nil
}
