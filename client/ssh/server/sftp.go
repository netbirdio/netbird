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
	s.mu.RLock()
	allowSFTP := s.allowSFTP
	s.mu.RUnlock()

	if !allowSFTP {
		log.Debugf("SFTP subsystem request denied: SFTP disabled")
		if err := sess.Exit(1); err != nil {
			log.Debugf("SFTP session exit failed: %v", err)
		}
		return
	}

	result := s.CheckPrivileges(PrivilegeCheckRequest{
		RequestedUsername:         sess.User(),
		FeatureSupportsUserSwitch: true,
		FeatureName:               FeatureSFTP,
	})

	if !result.Allowed {
		log.Warnf("SFTP access denied for user %s from %s: %v", sess.User(), sess.RemoteAddr(), result.Error)
		if err := sess.Exit(1); err != nil {
			log.Debugf("exit SFTP session: %v", err)
		}
		return
	}

	log.Debugf("SFTP subsystem request from user %s (effective user %s)", sess.User(), result.User.Username)

	if !result.RequiresUserSwitching {
		if err := s.executeSftpDirect(sess); err != nil {
			log.Errorf("SFTP direct execution: %v", err)
		}
		return
	}

	if err := s.executeSftpWithPrivilegeDrop(sess, result.User); err != nil {
		log.Errorf("SFTP privilege drop execution: %v", err)
	}
}

// executeSftpDirect executes SFTP directly without privilege dropping
func (s *Server) executeSftpDirect(sess ssh.Session) error {
	log.Debugf("starting SFTP session for user %s (no privilege dropping)", sess.User())

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
