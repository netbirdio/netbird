//go:build !windows

package client

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	nbssh "github.com/netbirdio/netbird/client/ssh"
)

func (c *Client) setupTerminalMode(ctx context.Context, session *ssh.Session) error {
	stdinFd := int(os.Stdin.Fd())

	if !term.IsTerminal(stdinFd) {
		return c.setupNonTerminalMode(ctx, session)
	}

	fd := int(os.Stdin.Fd())

	state, err := term.MakeRaw(fd)
	if err != nil {
		return c.setupNonTerminalMode(ctx, session)
	}

	if err := c.setupTerminal(session, fd); err != nil {
		if restoreErr := term.Restore(fd, state); restoreErr != nil {
			log.Debugf("restore terminal state: %v", restoreErr)
		}
		return err
	}

	c.terminalState = state
	c.terminalFd = fd

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	go func() {
		defer signal.Stop(sigChan)
		select {
		case <-ctx.Done():
			if err := term.Restore(fd, state); err != nil {
				log.Debugf("restore terminal state: %v", err)
			}
		case sig := <-sigChan:
			if err := term.Restore(fd, state); err != nil {
				log.Debugf("restore terminal state: %v", err)
			}
			signal.Reset(sig)
			s, ok := sig.(syscall.Signal)
			if !ok {
				log.Debugf("signal %v is not a syscall.Signal: %T", sig, sig)
				return
			}
			if err := syscall.Kill(syscall.Getpid(), s); err != nil {
				log.Debugf("kill process with signal %v: %v", s, err)
			}
		}
	}()

	return nil
}

func (c *Client) setupNonTerminalMode(_ context.Context, session *ssh.Session) error {
	return nil
}

// restoreWindowsConsoleState is a no-op on Unix systems
func (c *Client) restoreWindowsConsoleState() error {
	return nil
}

func (c *Client) setupTerminal(session *ssh.Session, fd int) error {
	w, h, err := term.GetSize(fd)
	if err != nil {
		return fmt.Errorf("get terminal size: %w", err)
	}

	modes := nbssh.DefaultTerminalModes

	terminal := os.Getenv("TERM")
	if terminal == "" {
		terminal = "xterm-256color"
	}

	if err := session.RequestPty(terminal, h, w, modes); err != nil {
		return fmt.Errorf("request pty: %w", err)
	}

	return nil
}
