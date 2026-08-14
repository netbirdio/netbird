package ssh

import (
	"fmt"
	"io"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

// defaultTerminalModes are the PTY modes used by the interactive terminal clients.
var defaultTerminalModes = ssh.TerminalModes{
	ssh.ECHO:          1,
	ssh.TTY_OP_ISPEED: 14400,
	ssh.TTY_OP_OSPEED: 14400,
	ssh.VINTR:         3,
	ssh.VQUIT:         28,
	ssh.VERASE:        127,
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
	if err := session.RequestPty("xterm-256color", rows, cols, defaultTerminalModes); err != nil {
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
