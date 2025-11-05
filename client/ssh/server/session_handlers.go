package server

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/gliderlabs/ssh"
	log "github.com/sirupsen/logrus"
)

// sessionHandler handles SSH sessions
func (s *Server) sessionHandler(session ssh.Session) {
	sessionKey := s.registerSession(session)
	logger := log.WithField("session", sessionKey)
	logger.Infof("SSH session started")
	sessionStart := time.Now()

	defer s.unregisterSession(sessionKey, session)
	defer func() {
		duration := time.Since(sessionStart).Round(time.Millisecond)
		if err := session.Close(); err != nil && !errors.Is(err, io.EOF) {
			logger.Warnf("close session after %v: %v", duration, err)
		}
		logger.Infof("SSH session closed after %v", duration)
	}()

	privilegeResult, err := s.userPrivilegeCheck(session.User())
	if err != nil {
		s.handlePrivError(logger, session, err)
		return
	}

	ptyReq, winCh, isPty := session.Pty()
	hasCommand := len(session.Command()) > 0

	switch {
	case isPty && hasCommand:
		// ssh -t <host> <cmd> - Pty command execution
		s.handleCommand(logger, session, privilegeResult, winCh)
	case isPty:
		// ssh <host> - Pty interactive session (login)
		s.handlePty(logger, session, privilegeResult, ptyReq, winCh)
	case hasCommand:
		// ssh <host> <cmd> - non-Pty command execution
		s.handleCommand(logger, session, privilegeResult, nil)
	default:
		s.rejectInvalidSession(logger, session)
	}
}

func (s *Server) rejectInvalidSession(logger *log.Entry, session ssh.Session) {
	if _, err := io.WriteString(session, "no command specified and Pty not requested\n"); err != nil {
		logger.Debugf(errWriteSession, err)
	}
	if err := session.Exit(1); err != nil {
		logSessionExitError(logger, err)
	}
	logger.Infof("rejected non-Pty session without command from %s", session.RemoteAddr())
}

func (s *Server) registerSession(session ssh.Session) SessionKey {
	sessionID := session.Context().Value(ssh.ContextKeySessionID)
	if sessionID == nil {
		sessionID = fmt.Sprintf("%p", session)
	}

	// Create a short 4-byte identifier from the full session ID
	hasher := sha256.New()
	hasher.Write([]byte(fmt.Sprintf("%v", sessionID)))
	hash := hasher.Sum(nil)
	shortID := hex.EncodeToString(hash[:4])

	remoteAddr := session.RemoteAddr().String()
	username := session.User()
	sessionKey := SessionKey(fmt.Sprintf("%s@%s-%s", username, remoteAddr, shortID))

	s.mu.Lock()
	s.sessions[sessionKey] = session
	s.mu.Unlock()

	return sessionKey
}

func (s *Server) unregisterSession(sessionKey SessionKey, _ ssh.Session) {
	s.mu.Lock()
	delete(s.sessions, sessionKey)

	// Cancel all port forwarding connections for this session
	var connectionsToCancel []ConnectionKey
	for key := range s.sessionCancels {
		if strings.HasPrefix(string(key), string(sessionKey)+"-") {
			connectionsToCancel = append(connectionsToCancel, key)
		}
	}

	for _, key := range connectionsToCancel {
		if cancelFunc, exists := s.sessionCancels[key]; exists {
			log.WithField("session", sessionKey).Debugf("cancelling port forwarding context: %s", key)
			cancelFunc()
			delete(s.sessionCancels, key)
		}
	}

	s.mu.Unlock()
}

func (s *Server) handlePrivError(logger *log.Entry, session ssh.Session, err error) {
	logger.Warnf("user privilege check failed: %v", err)

	errorMsg := s.buildUserLookupErrorMessage(err)

	if _, writeErr := fmt.Fprint(session, errorMsg); writeErr != nil {
		logger.Debugf(errWriteSession, writeErr)
	}
	if exitErr := session.Exit(1); exitErr != nil {
		logSessionExitError(logger, exitErr)
	}
}

// buildUserLookupErrorMessage creates appropriate user-facing error messages based on error type
func (s *Server) buildUserLookupErrorMessage(err error) string {
	var privilegedErr *PrivilegedUserError

	switch {
	case errors.As(err, &privilegedErr):
		if privilegedErr.Username == "root" {
			return "root login is disabled on this SSH server\n"
		}
		return "privileged user access is disabled on this SSH server\n"

	case errors.Is(err, ErrPrivilegeRequired):
		return "Windows user switching failed - NetBird must run with elevated privileges for user switching\n"

	case errors.Is(err, ErrPrivilegedUserSwitch):
		return "Cannot switch to privileged user - current user lacks required privileges\n"

	default:
		return "User authentication failed\n"
	}
}
