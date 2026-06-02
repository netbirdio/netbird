package server

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/gliderlabs/ssh"
	log "github.com/sirupsen/logrus"
)

// handleExecution executes an SSH command or shell with privilege validation
func (s *Server) handleExecution(logger *log.Entry, session ssh.Session, privilegeResult PrivilegeCheckResult, ptyReq ssh.Pty, winCh <-chan ssh.Window) {
	hasPty := winCh != nil

	commandType := "command"
	if hasPty {
		commandType = "Pty command"
	}

	logger.Infof("executing %s: %s", commandType, safeLogCommand(session.Command()))

	execCmd, cleanup, err := s.createCommand(logger, privilegeResult, session, hasPty)
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
			logSessionExitError(logger, err)
		}
		return
	}

	if !hasPty {
		if s.executeCommand(logger, session, execCmd, cleanup) {
			logger.Debugf("%s execution completed", commandType)
		}
		return
	}

	defer cleanup()

	if s.executeCommandWithPty(logger, session, execCmd, privilegeResult, ptyReq, winCh) {
		logger.Debugf("%s execution completed", commandType)
	}
}

func (s *Server) createCommand(logger *log.Entry, privilegeResult PrivilegeCheckResult, session ssh.Session, hasPty bool) (*exec.Cmd, func(), error) {
	localUser := privilegeResult.User
	if localUser == nil {
		return nil, nil, errors.New("no user in privilege result")
	}

	// If PTY requested but su doesn't support --pty, skip su and use executor
	// This ensures PTY functionality is provided (executor runs within our allocated PTY)
	if hasPty && !s.suSupportsPty {
		logger.Debugf("PTY requested but su doesn't support --pty, using executor for PTY functionality")
		cmd, cleanup, err := s.createExecutorCommand(logger, session, localUser, hasPty)
		if err != nil {
			return nil, nil, fmt.Errorf("create command with privileges: %w", err)
		}
		cmd.Env = s.prepareCommandEnv(logger, localUser, session)
		return cmd, cleanup, nil
	}

	// Try su first for system integration (PAM/audit) when privileged
	cmd, err := s.createSuCommand(logger, session, localUser, hasPty)
	if err != nil || privilegeResult.UsedFallback {
		logger.Debugf("su command failed, falling back to executor: %v", err)
		cmd, cleanup, err := s.createExecutorCommand(logger, session, localUser, hasPty)
		if err != nil {
			return nil, nil, fmt.Errorf("create command with privileges: %w", err)
		}
		cmd.Env = s.prepareCommandEnv(logger, localUser, session)
		return cmd, cleanup, nil
	}

	cmd.Env = s.prepareCommandEnv(logger, localUser, session)
	return cmd, func() {}, nil
}

// executeCommand executes the command and handles I/O and exit codes
func (s *Server) executeCommand(logger *log.Entry, session ssh.Session, execCmd *exec.Cmd, cleanup func()) bool {
	defer cleanup()

	s.setupProcessGroup(execCmd)

	stdinPipe, err := execCmd.StdinPipe()
	if err != nil {
		logger.Errorf("create stdin pipe: %v", err)
		if err := session.Exit(1); err != nil {
			logSessionExitError(logger, err)
		}
		return false
	}

	execCmd.Stdout = session
	execCmd.Stderr = session.Stderr()

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
			logSessionExitError(logger, err)
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
			logSessionExitError(logger, err)
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
			logSessionExitError(logger, err)
		}
		return
	}

	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		if err := session.Exit(exitError.ExitCode()); err != nil {
			logSessionExitError(logger, err)
		}
	} else {
		logger.Debugf("non-exit error in command execution: %v", err)
		if err := session.Exit(1); err != nil {
			logSessionExitError(logger, err)
		}
	}
}
