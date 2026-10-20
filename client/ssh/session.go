package ssh

import (
	"fmt"
	"io"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

// DefaultTerminalModes are the PTY modes used by the interactive terminal clients.
var DefaultTerminalModes = ssh.TerminalModes{
	ssh.ECHO:          1,
	ssh.TTY_OP_ISPEED: 14400,
	ssh.TTY_OP_OSPEED: 14400,
	ssh.VINTR:         3,   // Ctrl+C
	ssh.VQUIT:         28,  // Ctrl+\
	ssh.VERASE:        127, // Backspace
	ssh.VKILL:         21,  // Ctrl+U
	ssh.VEOF:          4,   // Ctrl+D
	ssh.VEOL:          0,
	ssh.VEOL2:         0,
	ssh.VSTART:        17, // Ctrl+Q
	ssh.VSTOP:         19, // Ctrl+S
	ssh.VSUSP:         26, // Ctrl+Z
	ssh.VDISCARD:      15, // Ctrl+O
	ssh.VREPRINT:      18, // Ctrl+R
	ssh.VWERASE:       23, // Ctrl+W
	ssh.VLNEXT:        22, // Ctrl+V
}

// PTYSession is an interactive shell session with a PTY and its I/O pipes.
type PTYSession struct {
	Session *ssh.Session
	Stdin   io.WriteCloser
	Stdout  io.Reader
	Stderr  io.Reader
}

// StartPTYSession opens a session on the client, requests an xterm-256color PTY
// with the default terminal modes, wires up the I/O pipes and starts a shell.
// The session is closed on any error.
func StartPTYSession(client *ssh.Client, cols, rows int) (*PTYSession, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("new session: %w", err)
	}

	pty, err := setupPTYSession(session, cols, rows)
	if err != nil {
		if closeErr := session.Close(); closeErr != nil {
			log.Debugf("ssh: session close after setup error: %v", closeErr)
		}
		return nil, err
	}
	return pty, nil
}

// setupPTYSession requests the PTY, opens the pipes and starts the shell on an
// already created session.
func setupPTYSession(session *ssh.Session, cols, rows int) (*PTYSession, error) {
	if err := session.RequestPty("xterm-256color", rows, cols, DefaultTerminalModes); err != nil {
		return nil, fmt.Errorf("request pty: %w", err)
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("stdin pipe: %w", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("stderr pipe: %w", err)
	}

	if err := session.Shell(); err != nil {
		return nil, fmt.Errorf("start shell: %w", err)
	}

	return &PTYSession{Session: session, Stdin: stdin, Stdout: stdout, Stderr: stderr}, nil
}
