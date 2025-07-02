package server

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"time"

	"github.com/gliderlabs/ssh"
	log "github.com/sirupsen/logrus"
)

// handleCommand executes an SSH command with privilege validation
func (s *Server) handleCommand(logger *log.Entry, session ssh.Session, privilegeResult PrivilegeCheckResult, ptyReq ssh.Pty, winCh <-chan ssh.Window) {
	localUser := privilegeResult.User
	hasPty := winCh != nil

	commandType := "command"
	if hasPty {
		commandType = "Pty command"
	}

	logger.Infof("executing %s for %s from %s: %s", commandType, localUser.Username, session.RemoteAddr(), safeLogCommand(session.Command()))

	execCmd, err := s.createCommandWithPrivileges(privilegeResult, session, hasPty)
	if err != nil {
		logger.Errorf("%s creation failed: %v", commandType, err)

		errorMsg := fmt.Sprintf("Cannot create %s - platform may not support user switching", commandType)
		if hasPty {
			errorMsg += " with Pty"
		}
		errorMsg += "\n"

		if _, writeErr := fmt.Fprint(session.Stderr(), errorMsg); writeErr != nil {
			logger.Debugf(errWriteSession, writeErr)
		}
		if err := session.Exit(1); err != nil {
			logger.Debugf(errExitSession, err)
		}
		return
	}

	var success bool
	if hasPty {
		success = s.handlePty(logger, session, privilegeResult, ptyReq, winCh)
	} else {
		success = s.executeCommand(logger, session, execCmd)
	}

	if !success {
		return
	}

	logger.Debugf("%s execution completed", commandType)
}

func (s *Server) createCommandWithPrivileges(privilegeResult PrivilegeCheckResult, session ssh.Session, hasPty bool) (*exec.Cmd, error) {
	localUser := privilegeResult.User

	var cmd *exec.Cmd
	var err error

	// If we used fallback (unprivileged process), skip su and use direct execution
	if privilegeResult.UsedFallback {
		log.Debugf("using fallback - direct execution for current user")
		cmd, err = s.createDirectCommand(session, localUser)
	} else {
		// Try su first for system integration (PAM/audit) when privileged
		cmd, err = s.createSuCommand(session, localUser)
		if err != nil {
			// Always fall back to executor if su fails
			log.Debugf("su command failed, falling back to executor: %v", err)
			cmd, err = s.createExecutorCommand(session, localUser, hasPty)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("create command with privileges: %w", err)
	}

	cmd.Env = s.prepareCommandEnv(localUser, session)
	return cmd, nil
}

// getShellCommandArgs returns the shell command and arguments for executing a command string
func (s *Server) getShellCommandArgs(shell, cmdString string) []string {
	if runtime.GOOS == "windows" {
		if cmdString == "" {
			return []string{shell, "-NoLogo"}
		}
		return []string{shell, "-Command", cmdString}
	}

	if cmdString == "" {
		return []string{shell}
	}
	return []string{shell, "-c", cmdString}
}

// executeCommand executes the command and handles I/O and exit codes
func (s *Server) executeCommand(logger *log.Entry, session ssh.Session, execCmd *exec.Cmd) bool {
	s.setupProcessGroup(execCmd)

	stdinPipe, err := execCmd.StdinPipe()
	if err != nil {
		logger.Errorf("create stdin pipe: %v", err)
		if err := session.Exit(1); err != nil {
			logger.Debugf(errExitSession, err)
		}
		return false
	}

	execCmd.Stdout = session
	execCmd.Stderr = session

	if execCmd.Dir != "" {
		if _, err := os.Stat(execCmd.Dir); err != nil {
			logger.Warnf("working directory does not exist: %s (%v)", execCmd.Dir, err)
			execCmd.Dir = "/"
		}
	}

	if err := execCmd.Start(); err != nil {
		logger.Errorf("command start failed: %v", err)
		// no user message for exec failure, just exit
		if err := session.Exit(1); err != nil {
			logger.Debugf(errExitSession, err)
		}
		return false
	}

	go s.handleCommandIO(logger, stdinPipe, session)
	return s.waitForCommandCleanup(logger, session, execCmd)
}

// handleCommandIO manages stdin/stdout copying in a goroutine
func (s *Server) handleCommandIO(logger *log.Entry, stdinPipe io.WriteCloser, session ssh.Session) {
	defer func() {
		if err := stdinPipe.Close(); err != nil {
			logger.Debugf("stdin pipe close error: %v", err)
		}
	}()
	if _, err := io.Copy(stdinPipe, session); err != nil {
		logger.Debugf("stdin copy error: %v", err)
	}
}

// createPtyCommandWithPrivileges creates the exec.Cmd for Pty execution respecting privilege check results
func (s *Server) createPtyCommandWithPrivileges(cmd []string, privilegeResult PrivilegeCheckResult, ptyReq ssh.Pty, session ssh.Session) (*exec.Cmd, error) {
	localUser := privilegeResult.User

	if privilegeResult.RequiresUserSwitching {
		return s.createPtyUserSwitchCommand(cmd, localUser, ptyReq, session)
	}

	// No user switching needed - create direct Pty command
	shell := getUserShell(localUser.Uid)
	rawCmd := session.RawCommand()
	args := s.getShellCommandArgs(shell, rawCmd)
	execCmd := exec.CommandContext(session.Context(), args[0], args[1:]...)

	execCmd.Dir = localUser.HomeDir
	execCmd.Env = s.preparePtyEnv(localUser, ptyReq, session)
	return execCmd, nil
}

// preparePtyEnv prepares environment variables for Pty execution
func (s *Server) preparePtyEnv(localUser *user.User, ptyReq ssh.Pty, session ssh.Session) []string {
	termType := ptyReq.Term
	if termType == "" {
		termType = "xterm-256color"
	}

	env := prepareUserEnv(localUser, getUserShell(localUser.Uid))
	env = append(env, prepareSSHEnv(session)...)
	env = append(env, fmt.Sprintf("TERM=%s", termType))

	for _, v := range session.Environ() {
		if acceptEnv(v) {
			env = append(env, v)
		}
	}
	return env
}

// waitForCommandCleanup waits for command completion with session disconnect handling
func (s *Server) waitForCommandCleanup(logger *log.Entry, session ssh.Session, execCmd *exec.Cmd) bool {
	ctx := session.Context()
	done := make(chan error, 1)
	go func() {
		done <- execCmd.Wait()
	}()

	select {
	case <-ctx.Done():
		logger.Debugf("session cancelled, terminating command")
		s.killProcessGroup(execCmd)

		select {
		case err := <-done:
			logger.Tracef("command terminated after session cancellation: %v", err)
		case <-time.After(5 * time.Second):
			logger.Warnf("command did not terminate within 5 seconds after session cancellation")
		}

		if err := session.Exit(130); err != nil {
			logger.Debugf(errExitSession, err)
		}
		return false

	case err := <-done:
		return s.handleCommandCompletion(logger, session, err)
	}
}

// handleCommandCompletion handles command completion
func (s *Server) handleCommandCompletion(logger *log.Entry, session ssh.Session, err error) bool {
	if err != nil {
		logger.Debugf("command execution failed: %v", err)
		s.handleSessionExit(session, err, logger)
		return false
	}

	s.handleSessionExit(session, nil, logger)
	return true
}

// handleSessionExit handles command errors and sets appropriate exit codes
func (s *Server) handleSessionExit(session ssh.Session, err error, logger *log.Entry) {
	if err == nil {
		if err := session.Exit(0); err != nil {
			logger.Debugf(errExitSession, err)
		}
		return
	}

	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		if err := session.Exit(exitError.ExitCode()); err != nil {
			logger.Debugf(errExitSession, err)
		}
	} else {
		logger.Debugf("non-exit error in command execution: %v", err)
		if err := session.Exit(1); err != nil {
			logger.Debugf(errExitSession, err)
		}
	}
}
