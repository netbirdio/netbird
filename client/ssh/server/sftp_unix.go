//go:build !windows

package server

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"

	"github.com/gliderlabs/ssh"
	log "github.com/sirupsen/logrus"
)

// executeSftpWithPrivilegeDrop executes SFTP using Unix privilege dropping
func (s *Server) executeSftpWithPrivilegeDrop(sess ssh.Session, targetUser *user.User) error {
	uid, gid, groups, err := s.parseUserCredentials(targetUser)
	if err != nil {
		return fmt.Errorf("parse user credentials: %w", err)
	}

	sftpCmd, err := s.createSftpExecutorCommand(sess, uid, gid, groups, targetUser.HomeDir)
	if err != nil {
		return fmt.Errorf("create executor: %w", err)
	}

	sftpCmd.Stdin = sess
	sftpCmd.Stdout = sess
	sftpCmd.Stderr = sess.Stderr()

	log.Tracef("starting SFTP with privilege dropping to user %s (UID=%d, GID=%d)", targetUser.Username, uid, gid)

	if err := sftpCmd.Start(); err != nil {
		return fmt.Errorf("starting SFTP executor: %w", err)
	}

	if err := sftpCmd.Wait(); err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			log.Tracef("SFTP process exited with code %d", exitError.ExitCode())
			return nil
		}
		return fmt.Errorf("exec: %w", err)
	}

	return nil
}

// createSftpExecutorCommand creates a command that spawns netbird ssh sftp for privilege dropping
func (s *Server) createSftpExecutorCommand(sess ssh.Session, uid, gid uint32, groups []uint32, workingDir string) (*exec.Cmd, error) {
	netbirdPath, err := os.Executable()
	if err != nil {
		return nil, err
	}

	args := []string{
		"ssh", "sftp",
		"--uid", strconv.FormatUint(uint64(uid), 10),
		"--gid", strconv.FormatUint(uint64(gid), 10),
		"--working-dir", workingDir,
	}

	for _, group := range groups {
		args = append(args, "--groups", strconv.FormatUint(uint64(group), 10))
	}

	log.Tracef("creating SFTP executor command: %s %v", netbirdPath, args)
	return exec.CommandContext(sess.Context(), netbirdPath, args...), nil
}
