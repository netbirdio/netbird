//go:build js

package server

import (
	"errors"
	"os/exec"
	"os/user"

	"github.com/gliderlabs/ssh"
)

var errNotSupported = errors.New("SSH server command execution not supported on WASM/JS platform")

// createSuCommand is not supported on JS/WASM
func (s *Server) createSuCommand(_ ssh.Session, _ *user.User, _ bool) (*exec.Cmd, error) {
	return nil, errNotSupported
}

// createExecutorCommand is not supported on JS/WASM
func (s *Server) createExecutorCommand(_ ssh.Session, _ *user.User, _ bool) (*exec.Cmd, error) {
	return nil, errNotSupported
}

// prepareCommandEnv is not supported on JS/WASM
func (s *Server) prepareCommandEnv(_ *user.User, _ ssh.Session) []string {
	return nil
}

// setupProcessGroup is not supported on JS/WASM
func (s *Server) setupProcessGroup(_ *exec.Cmd) {
}

// killProcessGroup is not supported on JS/WASM
func (s *Server) killProcessGroup(_ *exec.Cmd) {
}
