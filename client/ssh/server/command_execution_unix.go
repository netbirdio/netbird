//go:build unix

package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
	log "github.com/sirupsen/logrus"
)

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
		return errors.New("pty is closed")
	}
	return pty.Setsize(pm.file, ws)
}

func (pm *ptyManager) File() *os.File {
	return pm.file
}

// detectSuPtySupport checks if su supports the --pty flag
func (s *Server) detectSuPtySupport(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	cmd := exec.CommandContext(ctx, "su", "--help")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Debugf("su --help failed (may not support --help): %v", err)
		return false
	}

	supported := strings.Contains(string(output), "--pty")
	log.Debugf("su --pty support detected: %v", supported)
	return supported
}

// detectUtilLinuxLogin checks if login is from util-linux (vs shadow-utils).
// util-linux login uses vhangup() which requires setsid wrapper to avoid killing parent.
// See https://bugs.debian.org/1078023 for details.
func (s *Server) detectUtilLinuxLogin(ctx context.Context) bool {
	if runtime.GOOS != "linux" {
		return false
	}

	ctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	cmd := exec.CommandContext(ctx, "login", "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Debugf("login --version failed (likely shadow-utils): %v", err)
		return false
	}

	isUtilLinux := strings.Contains(string(output), "util-linux")
	log.Debugf("util-linux login detected: %v", isUtilLinux)
	return isUtilLinux
}

// createSuCommand creates a command using su - for privilege switching.
func (s *Server) createSuCommand(logger *log.Entry, session ssh.Session, localUser *user.User, hasPty bool) (*exec.Cmd, error) {
	if err := validateUsername(localUser.Username); err != nil {
		return nil, fmt.Errorf("invalid username %q: %w", localUser.Username, err)
	}

	suPath, err := exec.LookPath("su")
	if err != nil {
		return nil, fmt.Errorf("su command not available: %w", err)
	}

	args := []string{"-"}
	if hasPty && s.suSupportsPty {
		args = append(args, "--pty")
	}
	args = append(args, localUser.Username)

	command := session.RawCommand()
	if command != "" {
		args = append(args, "-c", command)
	}

	logger.Debugf("creating su command: %s %v", suPath, args)
	cmd := exec.CommandContext(session.Context(), suPath, args...)
	cmd.Dir = localUser.HomeDir

	return cmd, nil
}

// getShellCommandArgs returns the shell command and arguments for executing a command string.
func (s *Server) getShellCommandArgs(shell, cmdString string) []string {
	if cmdString == "" {
		return []string{shell}
	}
	return []string{shell, "-c", cmdString}
}

// createShellCommand creates an exec.Cmd configured as a login shell by setting argv[0] to "-shellname".
func (s *Server) createShellCommand(ctx context.Context, shell string, args []string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, shell, args[1:]...)
	cmd.Args[0] = "-" + filepath.Base(shell)
	return cmd
}

// prepareCommandEnv prepares environment variables for command execution on Unix
func (s *Server) prepareCommandEnv(_ *log.Entry, localUser *user.User, session ssh.Session) []string {
	env := prepareUserEnv(localUser, getUserShell(localUser.Uid))
	env = append(env, prepareSSHEnv(session)...)
	for _, v := range session.Environ() {
		if acceptEnv(v) {
			env = append(env, v)
		}
	}
	return env
}

// executeCommandWithPty executes a command with PTY allocation
func (s *Server) executeCommandWithPty(logger *log.Entry, session ssh.Session, execCmd *exec.Cmd, privilegeResult PrivilegeCheckResult, ptyReq ssh.Pty, winCh <-chan ssh.Window) bool {
	termType := ptyReq.Term
	if termType == "" {
		termType = "xterm-256color"
	}
	execCmd.Env = append(execCmd.Env, fmt.Sprintf("TERM=%s", termType))

	return s.runPtyCommand(logger, session, execCmd, ptyReq, winCh)
}

func (s *Server) handlePtyLogin(logger *log.Entry, session ssh.Session, privilegeResult PrivilegeCheckResult, ptyReq ssh.Pty, winCh <-chan ssh.Window) bool {
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

	logger.Infof("starting interactive shell: %s", strings.Join(execCmd.Args, " "))
	return s.runPtyCommand(logger, session, execCmd, ptyReq, winCh)
}

// runPtyCommand runs a command with PTY management (common code for interactive and command execution)
func (s *Server) runPtyCommand(logger *log.Entry, session ssh.Session, execCmd *exec.Cmd, ptyReq ssh.Pty, winCh <-chan ssh.Window) bool {
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
		s.handlePtyCommandCompletion(logger, session, ptyMgr, err)
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

func (s *Server) handlePtyCommandCompletion(logger *log.Entry, session ssh.Session, ptyMgr *ptyManager, err error) {
	if err != nil {
		logger.Debugf("Pty command execution failed: %v", err)
		s.handleSessionExit(session, err, logger)
	} else {
		logger.Debugf("Pty command completed successfully")
		if err := session.Exit(0); err != nil {
			logSessionExitError(logger, err)
		}
	}

	// Close PTY to unblock io.Copy goroutines
	if err := ptyMgr.Close(); err != nil {
		logger.Debugf("Pty close after completion: %v", err)
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
		logger.Debugf("kill process group SIGTERM: %v", err)
		return
	}

	const gracePeriod = 500 * time.Millisecond
	const checkInterval = 50 * time.Millisecond

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	timeout := time.After(gracePeriod)

	for {
		select {
		case <-timeout:
			if err := syscall.Kill(-pgid, syscall.SIGKILL); err != nil {
				logger.Debugf("kill process group SIGKILL: %v", err)
			}
			return
		case <-ticker.C:
			if err := syscall.Kill(-pgid, 0); err != nil {
				return
			}
		}
	}
}
