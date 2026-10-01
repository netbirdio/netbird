//go:build js

package server

import (
	"context"
	"errors"
	"os/exec"
	"os/user"

	"github.com/gliderlabs/ssh"
	log "github.com/sirupsen/logrus"
)

var errNotSupported = errors.New("SSH server command execution not supported on WASM/JS platform")

// createSuCommand is not supported on JS/WASM
func (s *Server) createSuCommand(_ *log.Entry, _ ssh.Session, _ *user.User, _ bool) (*exec.Cmd, error) {
	return nil, errNotSupported
}

// createExecutorCommand is not supported on JS/WASM
func (s *Server) createExecutorCommand(_ *log.Entry, _ ssh.Session, _ *user.User, _ bool) (*exec.Cmd, func(), error) {
	return nil, nil, errNotSupported
}

// prepareCommandEnv is not supported on JS/WASM
func (s *Server) prepareCommandEnv(_ *log.Entry, _ *user.User, _ ssh.Session) []string {
	return nil
}

// setupProcessGroup is not supported on JS/WASM
func (s *Server) setupProcessGroup(_ *exec.Cmd) {
}

// killProcessGroup is not supported on JS/WASM
func (s *Server) killProcessGroup(*exec.Cmd) {
}

// detectSuPtySupport always returns false on JS/WASM
func (s *Server) detectSuPtySupport(context.Context) bool {
	return false
}

// detectUtilLinuxLogin always returns false on JS/WASM
func (s *Server) detectUtilLinuxLogin(context.Context) bool {
	return false
}

// executeCommandWithPty is not supported on JS/WASM
func (s *Server) executeCommandWithPty(logger *log.Entry, session ssh.Session, execCmd *exec.Cmd, privilegeResult PrivilegeCheckResult, ptyReq ssh.Pty, winCh <-chan ssh.Window) bool {
	logger.Errorf("PTY command execution not supported on JS/WASM")
	if err := session.Exit(1); err != nil {
		logSessionExitError(logger, err)
	}
	return false
}
