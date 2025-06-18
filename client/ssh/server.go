package ssh

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
	"github.com/runletapp/go-console"
	log "github.com/sirupsen/logrus"
)

// DefaultSSHPort is the default SSH port of the NetBird's embedded SSH server
const DefaultSSHPort = 22022

// Error message constants
const (
	errWriteSession = "write session error: %v"
	errExitSession  = "exit session error: %v"
	defaultShell    = "/bin/sh"

	// Windows shell executables
	cmdExe        = "cmd.exe"
	powershellExe = "powershell.exe"
	pwshExe       = "pwsh.exe"

	// Shell detection strings
	powershellName = "powershell"
	pwshName       = "pwsh"
)

// safeLogCommand returns a safe representation of the command for logging
// Only logs the first argument to avoid leaking sensitive information
func safeLogCommand(cmd []string) string {
	if len(cmd) == 0 {
		return "<empty>"
	}
	if len(cmd) == 1 {
		return cmd[0]
	}
	return fmt.Sprintf("%s [%d args]", cmd[0], len(cmd)-1)
}

// NewServer creates an SSH server
func NewServer(hostKeyPEM []byte) *Server {
	return &Server{
		mu:             sync.RWMutex{},
		hostKeyPEM:     hostKeyPEM,
		authorizedKeys: make(map[string]ssh.PublicKey),
		sessions:       make(map[string]ssh.Session),
	}
}

// Server is the SSH server implementation
type Server struct {
	listener net.Listener
	// authorizedKeys maps peer IDs to their SSH public keys
	authorizedKeys map[string]ssh.PublicKey
	mu             sync.RWMutex
	hostKeyPEM     []byte
	sessions       map[string]ssh.Session
	running        bool
	cancel         context.CancelFunc
}

// RemoveAuthorizedKey removes the SSH key for a peer
func (s *Server) RemoveAuthorizedKey(peer string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.authorizedKeys, peer)
}

// AddAuthorizedKey adds an SSH key for a peer
func (s *Server) AddAuthorizedKey(peer, newKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	parsedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(newKey))
	if err != nil {
		return fmt.Errorf("parse key: %w", err)
	}

	s.authorizedKeys[peer] = parsedKey
	return nil
}

// Stop closes the SSH server
func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	// Set running to false first to prevent new operations
	s.running = false

	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}

	var closeErr error
	if s.listener != nil {
		closeErr = s.listener.Close()
		s.listener = nil
	}

	// Sessions will close themselves when context is cancelled
	// Don't manually close sessions here to avoid double-close

	if closeErr != nil {
		return fmt.Errorf("close listener: %w", closeErr)
	}
	return nil
}

func (s *Server) publicKeyHandler(_ ssh.Context, key ssh.PublicKey) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, allowed := range s.authorizedKeys {
		if ssh.KeysEqual(allowed, key) {
			return true
		}
	}

	return false
}

func prepareUserEnv(user *user.User, shell string) []string {
	return []string{
		fmt.Sprint("SHELL=" + shell),
		fmt.Sprint("USER=" + user.Username),
		fmt.Sprint("HOME=" + user.HomeDir),
	}
}

func acceptEnv(s string) bool {
	split := strings.Split(s, "=")
	if len(split) != 2 {
		return false
	}
	return split[0] == "TERM" || split[0] == "LANG" || strings.HasPrefix(split[0], "LC_")
}

// sessionHandler handles SSH sessions
func (s *Server) sessionHandler(session ssh.Session) {
	sessionKey := s.registerSession(session)
	sessionStart := time.Now()
	defer s.unregisterSession(sessionKey, session)
	defer func() {
		duration := time.Since(sessionStart)
		if err := session.Close(); err != nil {
			log.WithField("session", sessionKey).Debugf("close session after %v: %v", duration, err)
		} else {
			log.WithField("session", sessionKey).Debugf("session closed after %v", duration)
		}
	}()

	log.WithField("session", sessionKey).Infof("establishing SSH session for %s from %s", session.User(), session.RemoteAddr())

	localUser, err := userNameLookup(session.User())
	if err != nil {
		s.handleUserLookupError(sessionKey, session, err)
		return
	}

	ptyReq, winCh, isPty := session.Pty()
	if !isPty {
		s.handleNonPTYSession(sessionKey, session)
		return
	}

	// Check if this is a command execution request with PTY
	cmd := session.Command()
	if len(cmd) > 0 {
		s.handlePTYCommandExecution(sessionKey, session, localUser, ptyReq, winCh, cmd)
	} else {
		s.handlePTYSession(sessionKey, session, localUser, ptyReq, winCh)
	}
	log.WithField("session", sessionKey).Debugf("SSH session ended")
}

func (s *Server) registerSession(session ssh.Session) string {
	// Get session ID for hashing
	sessionID := session.Context().Value(ssh.ContextKeySessionID)
	if sessionID == nil {
		sessionID = fmt.Sprintf("%p", session)
	}

	// Create a short 4-byte identifier from the full session ID
	hasher := sha256.New()
	hasher.Write([]byte(fmt.Sprintf("%v", sessionID)))
	hash := hasher.Sum(nil)
	shortID := hex.EncodeToString(hash[:4]) // First 4 bytes = 8 hex chars

	// Create human-readable session key: user@IP:port-shortID
	remoteAddr := session.RemoteAddr().String()
	username := session.User()
	sessionKey := fmt.Sprintf("%s@%s-%s", username, remoteAddr, shortID)

	s.mu.Lock()
	s.sessions[sessionKey] = session
	s.mu.Unlock()

	log.WithField("session", sessionKey).Debugf("registered SSH session")
	return sessionKey
}

func (s *Server) unregisterSession(sessionKey string, _ ssh.Session) {
	s.mu.Lock()
	delete(s.sessions, sessionKey)
	s.mu.Unlock()
	log.WithField("session", sessionKey).Debugf("unregistered SSH session")
}

func (s *Server) handleUserLookupError(sessionKey string, session ssh.Session, err error) {
	logger := log.WithField("session", sessionKey)
	if _, writeErr := fmt.Fprintf(session, "remote SSH server couldn't find local user %s\n", session.User()); writeErr != nil {
		logger.Debugf(errWriteSession, writeErr)
	}
	if exitErr := session.Exit(1); exitErr != nil {
		logger.Debugf(errExitSession, exitErr)
	}
	logger.Warnf("user lookup failed: %v, user %s from %s", err, session.User(), session.RemoteAddr())
}

func (s *Server) handleNonPTYSession(sessionKey string, session ssh.Session) {
	logger := log.WithField("session", sessionKey)

	cmd := session.Command()
	if len(cmd) == 0 {
		// No command specified and no PTY - reject
		if _, err := io.WriteString(session, "no command specified and PTY not requested\n"); err != nil {
			logger.Debugf(errWriteSession, err)
		}
		if err := session.Exit(1); err != nil {
			logger.Debugf(errExitSession, err)
		}
		logger.Infof("rejected non-PTY session without command from %s", session.RemoteAddr())
		return
	}

	s.handleCommandExecution(sessionKey, session, cmd)
}

func (s *Server) handleCommandExecution(sessionKey string, session ssh.Session, cmd []string) {
	logger := log.WithField("session", sessionKey)

	localUser, err := userNameLookup(session.User())
	if err != nil {
		s.handleUserLookupError(sessionKey, session, err)
		return
	}

	logger.Infof("executing command for %s from %s: %s", session.User(), session.RemoteAddr(), safeLogCommand(cmd))

	execCmd := s.createCommand(cmd, localUser, session)
	if execCmd == nil {
		if err := session.Exit(1); err != nil {
			logger.Debugf(errExitSession, err)
		}
		return
	}

	if !s.executeCommand(sessionKey, session, execCmd) {
		return
	}

	logger.Debugf("command execution completed")
}

// createCommand creates the exec.Cmd for the given command and user
func (s *Server) createCommand(cmd []string, localUser *user.User, session ssh.Session) *exec.Cmd {
	shell := getUserShell(localUser.Uid)
	cmdString := strings.Join(cmd, " ")
	args := s.getShellCommandArgs(shell, cmdString)
	execCmd := exec.Command(args[0], args[1:]...)

	execCmd.Dir = localUser.HomeDir
	execCmd.Env = s.prepareCommandEnv(localUser, session)
	return execCmd
}

// getShellCommandArgs returns the shell command and arguments for executing a command string
func (s *Server) getShellCommandArgs(shell, cmdString string) []string {
	if runtime.GOOS == "windows" {
		shellLower := strings.ToLower(shell)
		if strings.Contains(shellLower, powershellName) || strings.Contains(shellLower, pwshName) {
			return []string{shell, "-Command", cmdString}
		} else {
			return []string{shell, "/c", cmdString}
		}
	}

	return []string{shell, "-c", cmdString}
}

// prepareCommandEnv prepares environment variables for command execution
func (s *Server) prepareCommandEnv(localUser *user.User, session ssh.Session) []string {
	env := prepareUserEnv(localUser, getUserShell(localUser.Uid))
	for _, v := range session.Environ() {
		if acceptEnv(v) {
			env = append(env, v)
		}
	}
	return env
}

// executeCommand executes the command and handles I/O and exit codes
func (s *Server) executeCommand(sessionKey string, session ssh.Session, execCmd *exec.Cmd) bool {
	logger := log.WithField("session", sessionKey)

	stdinPipe, err := execCmd.StdinPipe()
	if err != nil {
		logger.Debugf("create stdin pipe failed: %v", err)
		if err := session.Exit(1); err != nil {
			logger.Debugf(errExitSession, err)
		}
		return false
	}

	execCmd.Stdout = session
	execCmd.Stderr = session

	if err := execCmd.Start(); err != nil {
		logger.Debugf("command start failed: %v", err)
		if err := session.Exit(1); err != nil {
			logger.Debugf(errExitSession, err)
		}
		return false
	}

	s.handleCommandIO(sessionKey, stdinPipe, session)
	return s.waitForCommandCompletion(sessionKey, session, execCmd)
}

// handleCommandIO manages stdin/stdout copying in a goroutine
func (s *Server) handleCommandIO(sessionKey string, stdinPipe io.WriteCloser, session ssh.Session) {
	logger := log.WithField("session", sessionKey)

	go func() {
		defer func() {
			if err := stdinPipe.Close(); err != nil {
				logger.Debugf("stdin pipe close error: %v", err)
			}
		}()
		if _, err := io.Copy(stdinPipe, session); err != nil {
			logger.Debugf("stdin copy error: %v", err)
		}
	}()
}

// waitForCommandCompletion waits for command completion and handles exit codes
func (s *Server) waitForCommandCompletion(sessionKey string, session ssh.Session, execCmd *exec.Cmd) bool {
	logger := log.WithField("session", sessionKey)

	if err := execCmd.Wait(); err != nil {
		logger.Debugf("command execution failed: %v", err)
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			if err := session.Exit(exitError.ExitCode()); err != nil {
				logger.Debugf(errExitSession, err)
			}
		} else {
			if _, writeErr := fmt.Fprintf(session.Stderr(), "failed to execute command: %v\n", err); writeErr != nil {
				logger.Debugf(errWriteSession, writeErr)
			}
			if err := session.Exit(1); err != nil {
				logger.Debugf(errExitSession, err)
			}
		}
		return false
	}

	if err := session.Exit(0); err != nil {
		logger.Debugf(errExitSession, err)
	}
	return true
}

func (s *Server) handlePTYCommandExecution(sessionKey string, session ssh.Session, localUser *user.User, ptyReq ssh.Pty, winCh <-chan ssh.Window, cmd []string) {
	logger := log.WithField("session", sessionKey)
	logger.Infof("executing PTY command for %s from %s: %s", session.User(), session.RemoteAddr(), safeLogCommand(cmd))

	execCmd := s.createPTYCommand(cmd, localUser, ptyReq, session)
	if execCmd == nil {
		if err := session.Exit(1); err != nil {
			logger.Debugf(errExitSession, err)
		}
		return
	}

	ptyFile, err := s.startPTYCommand(execCmd)
	if err != nil {
		logger.Errorf("PTY start failed: %v", err)
		if err := session.Exit(1); err != nil {
			logger.Debugf(errExitSession, err)
		}
		return
	}
	defer func() {
		if err := ptyFile.Close(); err != nil {
			logger.Debugf("PTY file close error: %v", err)
		}
	}()

	s.handlePTYWindowResize(sessionKey, session, ptyFile, winCh)
	s.handlePTYIO(sessionKey, session, ptyFile)
	s.waitForPTYCompletion(sessionKey, session, execCmd)
}

// createPTYCommand creates the exec.Cmd for PTY execution
func (s *Server) createPTYCommand(cmd []string, localUser *user.User, ptyReq ssh.Pty, session ssh.Session) *exec.Cmd {
	shell := getUserShell(localUser.Uid)

	cmdString := strings.Join(cmd, " ")
	args := s.getShellCommandArgs(shell, cmdString)
	execCmd := exec.Command(args[0], args[1:]...)

	execCmd.Dir = localUser.HomeDir
	execCmd.Env = s.preparePTYEnv(localUser, ptyReq, session)
	return execCmd
}

// preparePTYEnv prepares environment variables for PTY execution
func (s *Server) preparePTYEnv(localUser *user.User, ptyReq ssh.Pty, session ssh.Session) []string {
	termType := ptyReq.Term
	if termType == "" {
		termType = "xterm-256color"
	}

	env := []string{
		fmt.Sprintf("TERM=%s", termType),
		"LANG=en_US.UTF-8",
		"LC_ALL=en_US.UTF-8",
	}
	env = append(env, prepareUserEnv(localUser, getUserShell(localUser.Uid))...)
	for _, v := range session.Environ() {
		if acceptEnv(v) {
			env = append(env, v)
		}
	}
	return env
}

// startPTYCommand starts the command with PTY
func (s *Server) startPTYCommand(execCmd *exec.Cmd) (*os.File, error) {
	ptyFile, err := pty.Start(execCmd)
	if err != nil {
		return nil, err
	}

	// Set initial PTY size to reasonable defaults if not set
	_ = pty.Setsize(ptyFile, &pty.Winsize{
		Rows: 24,
		Cols: 80,
	})

	return ptyFile, nil
}

// handlePTYWindowResize handles window resize events
func (s *Server) handlePTYWindowResize(sessionKey string, session ssh.Session, ptyFile *os.File, winCh <-chan ssh.Window) {
	logger := log.WithField("session", sessionKey)
	go func() {
		for {
			select {
			case <-session.Context().Done():
				return
			case win, ok := <-winCh:
				if !ok {
					return
				}
				if err := pty.Setsize(ptyFile, &pty.Winsize{
					Rows: uint16(win.Height),
					Cols: uint16(win.Width),
				}); err != nil {
					logger.Warnf("failed to resize PTY to %dx%d: %v", win.Width, win.Height, err)
				}
			}
		}
	}()
}

// handlePTYIO handles PTY input/output copying
func (s *Server) handlePTYIO(sessionKey string, session ssh.Session, ptyFile *os.File) {
	logger := log.WithField("session", sessionKey)

	go func() {
		defer func() {
			if err := ptyFile.Close(); err != nil {
				logger.Debugf("PTY file close error: %v", err)
			}
		}()
		if _, err := io.Copy(ptyFile, session); err != nil {
			logger.Debugf("PTY input copy error: %v", err)
		}
	}()

	go func() {
		defer func() {
			if err := session.Close(); err != nil {
				logger.Debugf("session close error: %v", err)
			}
		}()
		if _, err := io.Copy(session, ptyFile); err != nil {
			logger.Debugf("PTY output copy error: %v", err)
		}
	}()
}

// waitForPTYCompletion waits for PTY command completion and handles exit codes
func (s *Server) waitForPTYCompletion(sessionKey string, session ssh.Session, execCmd *exec.Cmd) {
	logger := log.WithField("session", sessionKey)

	if err := execCmd.Wait(); err != nil {
		logger.Debugf("PTY command execution failed: %v", err)
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			if err := session.Exit(exitError.ExitCode()); err != nil {
				logger.Debugf(errExitSession, err)
			}
		} else {
			if err := session.Exit(1); err != nil {
				logger.Debugf(errExitSession, err)
			}
		}
	} else {
		if err := session.Exit(0); err != nil {
			logger.Debugf(errExitSession, err)
		}
	}
}

func (s *Server) handlePTYSession(sessionKey string, session ssh.Session, localUser *user.User, ptyReq ssh.Pty, winCh <-chan ssh.Window) {
	logger := log.WithField("session", sessionKey)
	loginCmd, loginArgs, err := getLoginCmd(localUser.Username, session.RemoteAddr())
	if err != nil {
		logger.Warnf("login command setup failed: %v for user %s from %s", err, localUser.Username, session.RemoteAddr())
		return
	}

	proc, err := console.New(ptyReq.Window.Width, ptyReq.Window.Height)
	if err != nil {
		logger.Errorf("console creation failed: %v", err)
		return
	}
	defer func() {
		if err := proc.Close(); err != nil {
			logger.Debugf("close console: %v", err)
		}
	}()

	if err := s.setupConsoleProcess(sessionKey, proc, localUser, ptyReq, session); err != nil {
		logger.Errorf("console setup failed: %v", err)
		return
	}

	args := append([]string{loginCmd}, loginArgs...)
	logger.Debugf("login command: %s", args)
	if err := proc.Start(args); err != nil {
		logger.Errorf("console start failed: %v", err)
		return
	}

	// Setup window resizing and I/O
	go s.handleWindowResize(sessionKey, session.Context(), winCh, proc)
	go s.stdInOut(sessionKey, proc, session)

	processState, err := proc.Wait()
	if err != nil {
		logger.Debugf("console wait: %v", err)
		_ = session.Exit(1)
	} else {
		exitCode := processState.ExitCode()
		_ = session.Exit(exitCode)
	}
}

// setupConsoleProcess configures the console process environment
func (s *Server) setupConsoleProcess(sessionKey string, proc console.Console, localUser *user.User, ptyReq ssh.Pty, session ssh.Session) error {
	logger := log.WithField("session", sessionKey)

	// Set working directory
	if err := proc.SetCWD(localUser.HomeDir); err != nil {
		logger.Debugf("failed to set working directory: %v", err)
	}

	// Prepare environment variables
	env := []string{fmt.Sprintf("TERM=%s", ptyReq.Term)}
	env = append(env, prepareUserEnv(localUser, getUserShell(localUser.Uid))...)
	for _, v := range session.Environ() {
		if acceptEnv(v) {
			env = append(env, v)
		}
	}

	// Set environment variables
	if err := proc.SetENV(env); err != nil {
		logger.Debugf("failed to set environment: %v", err)
		return err
	}

	return nil
}

func (s *Server) handleWindowResize(sessionKey string, ctx context.Context, winCh <-chan ssh.Window, proc console.Console) {
	logger := log.WithField("session", sessionKey)
	for {
		select {
		case <-ctx.Done():
			return
		case win, ok := <-winCh:
			if !ok {
				return
			}
			if err := proc.SetSize(win.Width, win.Height); err != nil {
				logger.Warnf("failed to resize terminal window to %dx%d: %v", win.Width, win.Height, err)
			} else {
				logger.Debugf("resized terminal window to %dx%d", win.Width, win.Height)
			}
		}
	}
}

func (s *Server) stdInOut(sessionKey string, proc io.ReadWriter, session ssh.Session) {
	logger := log.WithField("session", sessionKey)

	// Copy stdin from session to process
	go func() {
		if _, err := io.Copy(proc, session); err != nil {
			logger.Debugf("stdin copy error: %v", err)
		}
	}()

	// Copy stdout from process to session
	go func() {
		if _, err := io.Copy(session, proc); err != nil {
			logger.Debugf("stdout copy error: %v", err)
		}
	}()

	// Wait for session to be done
	<-session.Context().Done()
}

// Start runs the SSH server
func (s *Server) Start(addr string) error {
	s.mu.Lock()

	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("server already running")
	}

	ctx, cancel := context.WithCancel(context.Background())
	lc := &net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		s.mu.Unlock()
		cancel()
		return fmt.Errorf("listen: %w", err)
	}

	s.running = true
	s.cancel = cancel
	s.listener = ln
	listenerAddr := ln.Addr().String()
	listenerCopy := ln

	s.mu.Unlock()

	log.Infof("starting SSH server on addr: %s", listenerAddr)

	// Ensure cleanup happens when Start() exits
	defer func() {
		s.mu.Lock()
		if s.running {
			s.running = false
			if s.cancel != nil {
				s.cancel()
				s.cancel = nil
			}
			s.listener = nil
		}
		s.mu.Unlock()
	}()

	done := make(chan error, 1)
	go func() {
		publicKeyOption := ssh.PublicKeyAuth(s.publicKeyHandler)
		hostKeyPEM := ssh.HostKeyPEM(s.hostKeyPEM)
		done <- ssh.Serve(listenerCopy, s.sessionHandler, publicKeyOption, hostKeyPEM)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		if err != nil {
			return fmt.Errorf("serve: %w", err)
		}
		return nil
	}
}

// getUserShell returns the appropriate shell for the given user ID
// Handles all platform-specific logic and fallbacks consistently
func getUserShell(userID string) string {
	switch runtime.GOOS {
	case "windows":
		return getWindowsUserShell()
	default:
		return getUnixUserShell(userID)
	}
}

// getWindowsUserShell returns the best shell for Windows users
// Order: pwsh.exe -> powershell.exe -> COMSPEC -> cmd.exe
func getWindowsUserShell() string {
	if _, err := exec.LookPath(pwshExe); err == nil {
		return pwshExe
	}
	if _, err := exec.LookPath(powershellExe); err == nil {
		return powershellExe
	}

	if comspec := os.Getenv("COMSPEC"); comspec != "" {
		return comspec
	}

	return cmdExe
}

// getUnixUserShell returns the shell for Unix-like systems
func getUnixUserShell(userID string) string {
	shell := getShellFromPasswd(userID)
	if shell != "" {
		return shell
	}

	if shell := os.Getenv("SHELL"); shell != "" {
		return shell
	}

	return defaultShell
}

// getShellFromPasswd reads the shell from /etc/passwd for the given user ID
func getShellFromPasswd(userID string) string {
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return ""
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Warnf("close /etc/passwd file: %v", err)
		}
	}()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, userID+":") {
			continue
		}

		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			return ""
		}

		shell := strings.TrimSpace(fields[6])
		return shell
	}

	return ""
}

func userNameLookup(username string) (*user.User, error) {
	if username == "" || (username == "root" && !isRoot()) {
		return user.Current()
	}

	u, err := user.Lookup(username)
	if err != nil {
		log.Warnf("user lookup failed for %s, falling back to current user: %v", username, err)
		return user.Current()
	}

	return u, nil
}
