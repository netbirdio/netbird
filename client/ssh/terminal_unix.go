//go:build !windows

package ssh

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

func (c *Client) setupTerminalMode(ctx context.Context, session *ssh.Session) error {
	fd := int(os.Stdout.Fd())

	if !term.IsTerminal(fd) {
		return c.setupNonTerminalMode(ctx, session)
	}

	state, err := term.MakeRaw(fd)
	if err != nil {
		return c.setupNonTerminalMode(ctx, session)
	}

	c.terminalState = state
	c.terminalFd = fd

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	go func() {
		defer signal.Stop(sigChan)
		select {
		case <-ctx.Done():
			_ = term.Restore(fd, state)
		case sig := <-sigChan:
			_ = term.Restore(fd, state)
			signal.Reset(sig)
			_ = syscall.Kill(syscall.Getpid(), sig.(syscall.Signal))
		}
	}()

	return c.setupTerminal(session, fd)
}

func (c *Client) setupNonTerminalMode(_ context.Context, session *ssh.Session) error {
	w, h := 80, 24

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
		return fmt.Errorf("request pty: %w", err)
	}

	return nil
}

// restoreWindowsConsoleState is a no-op on Unix systems
func (c *Client) restoreWindowsConsoleState() {
	// No-op on Unix systems
}

func (c *Client) setupTerminal(session *ssh.Session, fd int) error {
	w, h, err := term.GetSize(fd)
	if err != nil {
		return fmt.Errorf("get terminal size: %w", err)
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
		1:                 3,   // VINTR - Ctrl+C
		2:                 28,  // VQUIT - Ctrl+\
		3:                 127, // VERASE - Backspace
		4:                 21,  // VKILL - Ctrl+U
		5:                 4,   // VEOF - Ctrl+D
		6:                 0,   // VEOL
		7:                 0,   // VEOL2
		8:                 17,  // VSTART - Ctrl+Q
		9:                 19,  // VSTOP - Ctrl+S
		10:                26,  // VSUSP - Ctrl+Z
		18:                18,  // VREPRINT - Ctrl+R
		19:                23,  // VWERASE - Ctrl+W
		20:                22,  // VLNEXT - Ctrl+V
		21:                15,  // VDISCARD - Ctrl+O
	}

	terminal := os.Getenv("TERM")
	if terminal == "" {
		terminal = "xterm-256color"
	}

	if err := session.RequestPty(terminal, h, w, modes); err != nil {
		return fmt.Errorf("request pty: %w", err)
	}

	return nil
}
