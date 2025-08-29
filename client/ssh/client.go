package ssh

import (
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// Client wraps crypto/ssh Client to simplify usage
type Client struct {
	client *ssh.Client
}

// Close closes the wrapped SSH Client
func (c *Client) Close() error {
	return c.client.Close()
}

// OpenTerminal starts an interactive terminal session with the remote SSH server
func (c *Client) OpenTerminal() error {
	session, err := c.client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to open new session: %v", err)
	}
	defer func() {
		err := session.Close()
		if err != nil {
			return
		}
	}()

	fd := int(os.Stdout.Fd())
	state, err := term.MakeRaw(fd)
	if err != nil {
		return fmt.Errorf("failed to run raw terminal: %s", err)
	}
	defer func() {
		err := term.Restore(fd, state)
		if err != nil {
			return
		}
	}()

	w, h, err := term.GetSize(fd)
	if err != nil {
		return fmt.Errorf("terminal get size: %s", err)
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	terminal := os.Getenv("TERM")
	if terminal == "" {
		terminal = "xterm-256color"
	}
	if err := session.RequestPty(terminal, h, w, modes); err != nil {
		return fmt.Errorf("failed requesting pty session with xterm: %s", err)
	}

	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	session.Stdin = os.Stdin

	if err := session.Shell(); err != nil {
		return fmt.Errorf("failed to start login shell on the remote host: %s", err)
	}

	if err := session.Wait(); err != nil {
		if e, ok := err.(*ssh.ExitError); ok {
			if e.ExitStatus() == 130 {
				return nil
			}
		}
		return fmt.Errorf("failed running SSH session: %s", err)
	}

	return nil
}

// DialWithKey connects to the remote SSH server with a provided private key file (PEM).
func DialWithKey(addr, user string, privateKey []byte) (*Client, error) {

	signer, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	config := &ssh.ClientConfig{
		User:    user,
		Timeout: 5 * time.Second,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil }),
	}

	return Dial("tcp", addr, config)
}

// Dial connects to the remote SSH server.
func Dial(network, addr string, config *ssh.ClientConfig) (*Client, error) {
	client, err := ssh.Dial(network, addr, config)
	if err != nil {
		return nil, err
	}
	return &Client{
		client: client,
	}, nil
}
