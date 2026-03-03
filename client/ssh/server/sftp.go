package server

import (
	"fmt"
	"io"

	"github.com/gliderlabs/ssh"
	"github.com/pkg/sftp"
	log "github.com/sirupsen/logrus"
)

// SetAllowSFTP enables or disables SFTP support
func (s *Server) SetAllowSFTP(allow bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.allowSFTP = allow
}

// sftpSubsystemHandler handles SFTP subsystem requests
func (s *Server) sftpSubsystemHandler(sess ssh.Session) {
	sessionKey := s.registerSession(sess, cmdSFTP)
	defer s.unregisterSession(sessionKey)

	jwtUsername := s.associateJWTUsername(sess, sessionKey)

	logger := log.WithField("session", sessionKey)
	if jwtUsername != "" {
		logger = logger.WithField("jwt_user", jwtUsername)
	}
	logger.Info("SFTP session started")
	defer logger.Info("SFTP session closed")

	s.mu.RLock()
	allowSFTP := s.allowSFTP
	s.mu.RUnlock()

	if !allowSFTP {
		logger.Debug("SFTP subsystem request denied: SFTP disabled")
		if err := sess.Exit(1); err != nil {
			logger.Debugf("SFTP session exit: %v", err)
		}
		return
	}

	result := s.CheckPrivileges(PrivilegeCheckRequest{
		RequestedUsername:         sess.User(),
		FeatureSupportsUserSwitch: true,
		FeatureName:               FeatureSFTP,
	})

	if !result.Allowed {
		logger.Warnf("SFTP access denied: %v", result.Error)
		if err := sess.Exit(1); err != nil {
			logger.Debugf("exit SFTP session: %v", err)
		}
		return
	}

	if !result.RequiresUserSwitching {
		if err := s.executeSftpDirect(sess); err != nil {
			logger.Errorf("SFTP direct execution: %v", err)
		}
		return
	}

	if err := s.executeSftpWithPrivilegeDrop(sess, result.User); err != nil {
		logger.Errorf("SFTP privilege drop execution: %v", err)
	}
}

// executeSftpDirect executes SFTP directly without privilege dropping
func (s *Server) executeSftpDirect(sess ssh.Session) error {
	sftpServer, err := sftp.NewServer(sess)
	if err != nil {
		return fmt.Errorf("SFTP server creation: %w", err)
	}

	defer func() {
		if err := sftpServer.Close(); err != nil {
			log.Debugf("failed to close sftp server: %v", err)
		}
	}()

	if err := sftpServer.Serve(); err != nil && err != io.EOF {
		return fmt.Errorf("serve: %w", err)
	}

	return nil
}
