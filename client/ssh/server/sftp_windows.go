//go:build windows

package server

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"

	"github.com/gliderlabs/ssh"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

// createSftpCommand creates a Windows SFTP command with user switching
func (s *Server) createSftpCommand(targetUser *user.User, sess ssh.Session) (*exec.Cmd, error) {
	username, domain := s.parseUsername(targetUser.Username)

	netbirdPath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("get netbird executable path: %w", err)
	}

	args := []string{
		"ssh", "sftp",
		"--working-dir", targetUser.HomeDir,
		"--windows-username", username,
		"--windows-domain", domain,
	}

	pd := NewPrivilegeDropper()
	token, err := pd.createToken(username, domain)
	if err != nil {
		return nil, fmt.Errorf("create token: %w", err)
	}

	defer func() {
		if err := windows.CloseHandle(token); err != nil {
			log.Warnf("failed to close Windows token handle: %v", err)
		}
	}()

	cmd, err := pd.createProcessWithToken(sess.Context(), windows.Token(token), netbirdPath, append([]string{netbirdPath}, args...), targetUser.HomeDir)

	if err != nil {
		return nil, fmt.Errorf("create SFTP command: %w", err)
	}

	log.Debugf("Created Windows SFTP command with user switching for %s", targetUser.Username)
	return cmd, nil
}

// executeSftpCommand executes a Windows SFTP command with proper I/O handling
func (s *Server) executeSftpCommand(sess ssh.Session, sftpCmd *exec.Cmd) error {
	sftpCmd.Stdin = sess
	sftpCmd.Stdout = sess
	sftpCmd.Stderr = sess.Stderr()

	if err := sftpCmd.Start(); err != nil {
		return fmt.Errorf("starting sftp executor: %w", err)
	}

	if err := sftpCmd.Wait(); err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			log.Tracef("sftp process exited with code %d", exitError.ExitCode())
			return nil
		}

		return fmt.Errorf("exec sftp: %w", err)
	}

	return nil
}

// executeSftpWithPrivilegeDrop executes SFTP using Windows privilege dropping
func (s *Server) executeSftpWithPrivilegeDrop(sess ssh.Session, targetUser *user.User) error {
	sftpCmd, err := s.createSftpCommand(targetUser, sess)
	if err != nil {
		return fmt.Errorf("create sftp: %w", err)
	}
	return s.executeSftpCommand(sess, sftpCmd)
}
