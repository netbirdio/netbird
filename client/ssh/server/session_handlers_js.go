//go:build js

package server

import (
	"fmt"

	"github.com/gliderlabs/ssh"
	log "github.com/sirupsen/logrus"
)

// handlePty is not supported on JS/WASM
func (s *Server) handlePty(logger *log.Entry, session ssh.Session, _ PrivilegeCheckResult, _ ssh.Pty, _ <-chan ssh.Window) bool {
	errorMsg := "PTY sessions are not supported on WASM/JS platform\n"
	if _, err := fmt.Fprint(session.Stderr(), errorMsg); err != nil {
		logger.Debugf(errWriteSession, err)
	}
	if err := session.Exit(1); err != nil {
		logger.Debugf(errExitSession, err)
	}
	return false
}
