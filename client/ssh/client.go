package ssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// Client wraps crypto/ssh Client for simplified SSH operations
type Client struct {
	client        *ssh.Client
	terminalState *term.State
	terminalFd    int
	// Windows-specific console state
	windowsStdoutMode uint32
	windowsStdinMode  uint32
}

// Close terminates the SSH connection
func (c *Client) Close() error {
	return c.client.Close()
}

// OpenTerminal opens an interactive terminal session
func (c *Client) OpenTerminal(ctx context.Context) error {
	session, err := c.client.NewSession()
	if err != nil {
		return fmt.Errorf("new session: %w", err)
	}
	defer func() {
		_ = session.Close()
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
	if !errors.As(err, &e) {
		// Only return actual errors (not exit status errors)
		return fmt.Errorf("session wait: %w", err)
	}

	// SSH should behave like regular command execution:
	// Non-zero exit codes are normal and should not be treated as errors
	// The command ran successfully, it just returned a non-zero exit code
	return nil
}

// restoreTerminal restores the terminal to its original state
func (c *Client) restoreTerminal() {
	if c.terminalState != nil {
		_ = term.Restore(c.terminalFd, c.terminalState)
		c.terminalState = nil
		c.terminalFd = 0
	}

	// Windows console restoration
	c.restoreWindowsConsoleState()
}

// ExecuteCommand executes a command on the remote host and returns the output
func (c *Client) ExecuteCommand(ctx context.Context, command string) ([]byte, error) {
	session, cleanup, err := c.createSession(ctx)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	// Execute the command and capture output
	output, err := session.CombinedOutput(command)
	if err != nil {
		var e *ssh.ExitError
		if !errors.As(err, &e) {
			// Only return actual errors (not exit status errors)
			return output, fmt.Errorf("execute command: %w", err)
		}
		// SSH should behave like regular command execution:
		// Non-zero exit codes are normal and should not be treated as errors
		// Return the output even for non-zero exit codes
	}

	return output, nil
}

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
		return nil
	case err := <-done:
		return c.handleCommandError(err)
	}
}

func (c *Client) ExecuteCommandWithPTY(ctx context.Context, command string) error {
	session, cleanup, err := c.createSession(ctx)
	if err != nil {
		return err
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
		return nil
	case err := <-done:
		return c.handleCommandError(err)
	}
}

func (c *Client) handleCommandError(err error) error {
	if err == nil {
		return nil
	}

	var e *ssh.ExitError
	if !errors.As(err, &e) {
		// Only return actual errors (not exit status errors)
		return fmt.Errorf("execute command: %w", err)
	}

	// SSH should behave like regular command execution:
	// Non-zero exit codes are normal and should not be treated as errors
	// The command ran successfully, it just returned a non-zero exit code
	return nil
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

// DialWithKey connects using private key authentication
func DialWithKey(ctx context.Context, addr, user string, privateKey []byte) (*Client, error) {
	signer, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	config := &ssh.ClientConfig{
		User:    user,
		Timeout: 30 * time.Second,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil }),
	}

	return Dial(ctx, "tcp", addr, config)
}

// Dial establishes an SSH connection
func Dial(ctx context.Context, network, addr string, config *ssh.ClientConfig) (*Client, error) {
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	clientConn, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		if closeErr := conn.Close(); closeErr != nil {
			return nil, fmt.Errorf("ssh handshake: %w (failed to close connection: %v)", err, closeErr)
		}
		return nil, fmt.Errorf("ssh handshake: %w", err)
	}

	client := ssh.NewClient(clientConn, chans, reqs)
	return &Client{
		client: client,
	}, nil
}
