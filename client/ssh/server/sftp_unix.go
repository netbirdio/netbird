//go:build !windows

package server

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"

	"github.com/gliderlabs/ssh"
	log "github.com/sirupsen/logrus"
)

// sftpSession presents the SFTP server invocation as the session's command,
// so it can be started like any other command.
type sftpSession struct {
	ssh.Session
	command string
}

func (s sftpSession) RawCommand() string {
	return s.command
}

// executeSftpWithPrivilegeDrop executes SFTP as the target user using Unix privilege dropping
func (s *Server) executeSftpWithPrivilegeDrop(sess ssh.Session, targetUser *user.User) error {
	logger := log.WithField("user", targetUser.Username)

	sftpCmd, cleanup, err := s.createSftpCommand(logger, sess, targetUser)
	if err != nil {
		return fmt.Errorf("create SFTP command: %w", err)
	}

	logger.Tracef("starting SFTP with privilege dropping")

	if s.executeCommand(logger, sess, sftpCmd, cleanup) {
		logger.Debugf("SFTP execution completed")
	}

	return nil
}

// createSftpCommand creates a command that spawns netbird ssh sftp as the target user.
// The invocation goes through createCommand like a session command (su, or the executor
// with the user's shell), so the host's account restrictions (PAM, login shell) apply to
// SFTP as they do to shell and command sessions.
func (s *Server) createSftpCommand(logger *log.Entry, sess ssh.Session, targetUser *user.User) (*exec.Cmd, func(), error) {
	uid, gid, groups, err := s.parseUserCredentials(targetUser)
	if err != nil {
		return nil, nil, fmt.Errorf("parse user credentials: %w", err)
	}

	netbirdPath, err := os.Executable()
	if err != nil {
		return nil, nil, fmt.Errorf("get netbird executable path: %w", err)
	}

	args := []string{
		shellQuote(netbirdPath), "ssh", "sftp",
		"--uid", strconv.FormatUint(uint64(uid), 10),
		"--gid", strconv.FormatUint(uint64(gid), 10),
		"--working-dir", shellQuote(targetUser.HomeDir),
	}

	for _, group := range groups {
		args = append(args, "--groups", strconv.FormatUint(uint64(group), 10))
	}

	command := strings.Join(args, " ")
	logger.Tracef("creating SFTP command: %s", command)

	privilegeResult := PrivilegeCheckResult{
		Allowed:               true,
		User:                  targetUser,
		RequiresUserSwitching: true,
	}
	return s.createCommand(logger, privilegeResult, sftpSession{Session: sess, command: command}, false)
}

// shellQuote quotes s as a single word for a POSIX shell
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
