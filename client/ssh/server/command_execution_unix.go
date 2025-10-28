//go:build unix

package server

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
	log "github.com/sirupsen/logrus"
)

// createSuCommand creates a command using su -l -c for privilege switching
func (s *Server) createSuCommand(session ssh.Session, localUser *user.User, hasPty bool) (*exec.Cmd, error) {
	suPath, err := exec.LookPath("su")
	if err != nil {
		return nil, fmt.Errorf("su command not available: %w", err)
	}

	command := session.RawCommand()
	if command == "" {
		return nil, fmt.Errorf("no command specified for su execution")
	}

	// TODO: handle pty flag if available
	args := []string{"-l", localUser.Username, "-c", command}

	cmd := exec.CommandContext(session.Context(), suPath, args...)
	cmd.Dir = localUser.HomeDir

	return cmd, nil
}

// getShellCommandArgs returns the shell command and arguments for executing a command string
func (s *Server) getShellCommandArgs(shell, cmdString string) []string {
	if cmdString == "" {
		return []string{shell, "-l"}
	}
	return []string{shell, "-l", "-c", cmdString}
}

// prepareCommandEnv prepares environment variables for command execution on Unix
func (s *Server) prepareCommandEnv(localUser *user.User, session ssh.Session) []string {
	env := prepareUserEnv(localUser, getUserShell(localUser.Uid))
	env = append(env, prepareSSHEnv(session)...)
	for _, v := range session.Environ() {
		if acceptEnv(v) {
			env = append(env, v)
		}
	}
	return env
}

// ptyManager manages Pty file operations with thread safety
type ptyManager struct {
	file     *os.File
	mu       sync.RWMutex
	closed   bool
	closeErr error
	once     sync.Once
}

func newPtyManager(file *os.File) *ptyManager {
	return &ptyManager{file: file}
}

func (pm *ptyManager) Close() error {
	pm.once.Do(func() {
		pm.mu.Lock()
		pm.closed = true
		pm.closeErr = pm.file.Close()
		pm.mu.Unlock()
	})
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.closeErr
}

func (pm *ptyManager) Setsize(ws *pty.Winsize) error {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	if pm.closed {
		return errors.New("Pty is closed")
	}
	return pty.Setsize(pm.file, ws)
}

func (pm *ptyManager) File() *os.File {
	return pm.file
}

func (s *Server) handlePty(logger *log.Entry, session ssh.Session, privilegeResult PrivilegeCheckResult, ptyReq ssh.Pty, winCh <-chan ssh.Window) bool {
	cmd := session.Command()
	logger.Infof("executing Pty command: %s", safeLogCommand(cmd))

	execCmd, err := s.createPtyCommand(privilegeResult, ptyReq, session)
	if err != nil {
		logger.Errorf("Pty command creation failed: %v", err)
		errorMsg := "User switching failed - login command not available\r\n"
		if _, writeErr := fmt.Fprint(session.Stderr(), errorMsg); writeErr != nil {
			logger.Debugf(errWriteSession, writeErr)
		}
		if err := session.Exit(1); err != nil {
			logSessionExitError(logger, err)
		}
		return false
	}

	ptmx, err := s.startPtyCommandWithSize(execCmd, ptyReq)
	if err != nil {
		logger.Errorf("Pty start failed: %v", err)
		if err := session.Exit(1); err != nil {
			logSessionExitError(logger, err)
		}
		return false
	}

	ptyMgr := newPtyManager(ptmx)
	defer func() {
		if err := ptyMgr.Close(); err != nil {
			logger.Debugf("Pty close error: %v", err)
		}
	}()

	go s.handlePtyWindowResize(logger, session, ptyMgr, winCh)
	s.handlePtyIO(logger, session, ptyMgr)
	s.waitForPtyCompletion(logger, session, execCmd, ptyMgr)
	return true
}

func (s *Server) startPtyCommandWithSize(execCmd *exec.Cmd, ptyReq ssh.Pty) (*os.File, error) {
	winSize := &pty.Winsize{
		Cols: uint16(ptyReq.Window.Width),
		Rows: uint16(ptyReq.Window.Height),
	}
	if winSize.Cols == 0 {
		winSize.Cols = 80
	}
	if winSize.Rows == 0 {
		winSize.Rows = 24
	}

	ptmx, err := pty.StartWithSize(execCmd, winSize)
	if err != nil {
		return nil, fmt.Errorf("start Pty: %w", err)
	}

	return ptmx, nil
}

func (s *Server) handlePtyWindowResize(logger *log.Entry, session ssh.Session, ptyMgr *ptyManager, winCh <-chan ssh.Window) {
	for {
		select {
		case <-session.Context().Done():
			return
		case win, ok := <-winCh:
			if !ok {
				return
			}
			if err := ptyMgr.Setsize(&pty.Winsize{Rows: uint16(win.Height), Cols: uint16(win.Width)}); err != nil {
				logger.Debugf("Pty resize to %dx%d: %v", win.Width, win.Height, err)
			}
		}
	}
}

func (s *Server) handlePtyIO(logger *log.Entry, session ssh.Session, ptyMgr *ptyManager) {
	ptmx := ptyMgr.File()

	go func() {
		if _, err := io.Copy(ptmx, session); err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, syscall.EIO) {
				logger.Warnf("Pty input copy error: %v", err)
			}
		}
	}()

	go func() {
		defer func() {
			if err := session.Close(); err != nil && !errors.Is(err, io.EOF) {
				logger.Debugf("session close error: %v", err)
			}
		}()
		if _, err := io.Copy(session, ptmx); err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, syscall.EIO) {
				logger.Warnf("Pty output copy error: %v", err)
			}
		}
	}()
}

func (s *Server) waitForPtyCompletion(logger *log.Entry, session ssh.Session, execCmd *exec.Cmd, ptyMgr *ptyManager) {
	ctx := session.Context()
	done := make(chan error, 1)
	go func() {
		done <- execCmd.Wait()
	}()

	select {
	case <-ctx.Done():
		s.handlePtySessionCancellation(logger, session, execCmd, ptyMgr, done)
	case err := <-done:
		s.handlePtyCommandCompletion(logger, session, err)
	}
}

func (s *Server) handlePtySessionCancellation(logger *log.Entry, session ssh.Session, execCmd *exec.Cmd, ptyMgr *ptyManager, done <-chan error) {
	logger.Debugf("Pty session cancelled, terminating command")
	if err := ptyMgr.Close(); err != nil {
		logger.Debugf("Pty close during session cancellation: %v", err)
	}

	s.killProcessGroup(execCmd)

	select {
	case err := <-done:
		if err != nil {
			logger.Debugf("Pty command terminated after session cancellation with error: %v", err)
		} else {
			logger.Debugf("Pty command terminated after session cancellation")
		}
	case <-time.After(5 * time.Second):
		logger.Warnf("Pty command did not terminate within 5 seconds after session cancellation")
	}

	if err := session.Exit(130); err != nil {
		logSessionExitError(logger, err)
	}
}

func (s *Server) handlePtyCommandCompletion(logger *log.Entry, session ssh.Session, err error) {
	if err != nil {
		logger.Debugf("Pty command execution failed: %v", err)
		s.handleSessionExit(session, err, logger)
		return
	}

	// Normal completion
	logger.Debugf("Pty command completed successfully")
	if err := session.Exit(0); err != nil {
		logSessionExitError(logger, err)
	}
}

func (s *Server) setupProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
}

func (s *Server) killProcessGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}

	logger := log.WithField("pid", cmd.Process.Pid)
	pgid := cmd.Process.Pid

	if err := syscall.Kill(-pgid, syscall.SIGTERM); err != nil {
		logger.Debugf("kill process group SIGTERM failed: %v", err)
		if err := syscall.Kill(-pgid, syscall.SIGKILL); err != nil {
			logger.Debugf("kill process group SIGKILL failed: %v", err)
		}
	}
}
