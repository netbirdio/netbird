package server

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/gliderlabs/ssh"
	log "github.com/sirupsen/logrus"
)

// associateJWTUsername extracts pending JWT username for the session and associates it with the session state.
// Returns the JWT username (empty if none) for logging purposes.
func (s *Server) associateJWTUsername(sess ssh.Session, sessionKey sessionKey) string {
	key := newAuthKey(sess.User(), sess.RemoteAddr())

	s.mu.Lock()
	defer s.mu.Unlock()

	jwtUsername := s.pendingAuthJWT[key]
	if jwtUsername == "" {
		return ""
	}

	if state, exists := s.sessions[sessionKey]; exists {
		state.jwtUsername = jwtUsername
	}
	delete(s.pendingAuthJWT, key)
	return jwtUsername
}

// sessionHandler handles SSH sessions
func (s *Server) sessionHandler(session ssh.Session) {
	sessionKey := s.registerSession(session, "")
	jwtUsername := s.associateJWTUsername(session, sessionKey)

	logger := log.WithField("session", sessionKey)
	if jwtUsername != "" {
		logger = logger.WithField("jwt_user", jwtUsername)
	}
	logger.Info("SSH session started")
	sessionStart := time.Now()

	defer s.unregisterSession(sessionKey)
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
		// ssh -T (or ssh -N) - no PTY, no command
		s.handleNonInteractiveSession(logger, session)
	}
}

// handleNonInteractiveSession handles sessions that have no PTY and no command.
// These are typically used for port forwarding (ssh -L/-R) or tunneling (ssh -N).
func (s *Server) handleNonInteractiveSession(logger *log.Entry, session ssh.Session) {
	s.updateSessionType(session, cmdNonInteractive)

	if !s.isPortForwardingEnabled() {
		if _, err := io.WriteString(session, "port forwarding is disabled on this server\n"); err != nil {
			logger.Debugf(errWriteSession, err)
		}
		if err := session.Exit(1); err != nil {
			logSessionExitError(logger, err)
		}
		logger.Infof("rejected non-interactive session: port forwarding disabled")
		return
	}

	<-session.Context().Done()

	if err := session.Exit(0); err != nil {
		logSessionExitError(logger, err)
	}
}

func (s *Server) updateSessionType(session ssh.Session, sessionType string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, state := range s.sessions {
		if state.session == session {
			state.sessionType = sessionType
			return
		}
	}
}

func (s *Server) registerSession(session ssh.Session, sessionType string) sessionKey {
	sessionID := session.Context().Value(ssh.ContextKeySessionID)
	if sessionID == nil {
		sessionID = fmt.Sprintf("%p", session)
	}

	hasher := sha256.New()
	hasher.Write([]byte(fmt.Sprintf("%v", sessionID)))
	hash := hasher.Sum(nil)
	shortID := hex.EncodeToString(hash[:4])

	remoteAddr := session.RemoteAddr().String()
	username := session.User()
	sessionKey := sessionKey(fmt.Sprintf("%s@%s-%s", username, remoteAddr, shortID))

	s.mu.Lock()
	s.sessions[sessionKey] = &sessionState{
		session:     session,
		sessionType: sessionType,
	}
	s.mu.Unlock()

	return sessionKey
}

func (s *Server) unregisterSession(sessionKey sessionKey) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.sessions, sessionKey)
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
