//go:build unix

package server

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"runtime"
	"strconv"

	"github.com/gliderlabs/ssh"
	log "github.com/sirupsen/logrus"
)

// POSIX portable filename character set regex: [a-zA-Z0-9._-]
// First character cannot be hyphen (POSIX requirement)
var posixUsernameRegex = regexp.MustCompile(`^[a-zA-Z0-9._][a-zA-Z0-9._-]*$`)

// validateUsername validates that a username conforms to POSIX standards with security considerations
func validateUsername(username string) error {
	if username == "" {
		return errors.New("username cannot be empty")
	}

	// POSIX allows up to 256 characters, but practical limit is 32 for compatibility
	if len(username) > 32 {
		return errors.New("username too long (max 32 characters)")
	}

	if !posixUsernameRegex.MatchString(username) {
		return errors.New("username contains invalid characters (must match POSIX portable filename character set)")
	}

	if username == "." || username == ".." {
		return fmt.Errorf("username cannot be '.' or '..'")
	}

	// Warn if username is fully numeric (can cause issues with UID/username ambiguity)
	if isFullyNumeric(username) {
		log.Warnf("fully numeric username '%s' may cause issues with some commands", username)
	}

	return nil
}

// isFullyNumeric checks if username contains only digits
func isFullyNumeric(username string) bool {
	for _, char := range username {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

// createPtyLoginCommand creates a Pty command using login for privileged processes
func (s *Server) createPtyLoginCommand(localUser *user.User, ptyReq ssh.Pty, session ssh.Session) (*exec.Cmd, error) {
	loginPath, args, err := s.getLoginCmd(localUser.Username, session.RemoteAddr())
	if err != nil {
		return nil, fmt.Errorf("get login command: %w", err)
	}

	execCmd := exec.CommandContext(session.Context(), loginPath, args...)
	execCmd.Dir = localUser.HomeDir
	execCmd.Env = s.preparePtyEnv(localUser, ptyReq, session)

	return execCmd, nil
}

// getLoginCmd returns the login command and args for privileged Pty user switching
func (s *Server) getLoginCmd(username string, remoteAddr net.Addr) (string, []string, error) {
	loginPath, err := exec.LookPath("login")
	if err != nil {
		return "", nil, fmt.Errorf("login command not available: %w", err)
	}

	addrPort, err := netip.ParseAddrPort(remoteAddr.String())
	if err != nil {
		return "", nil, fmt.Errorf("parse remote address: %w", err)
	}

	switch runtime.GOOS {
	case "linux":
		p, a := s.getLinuxLoginCmd(loginPath, username, addrPort.Addr().String())
		return p, a, nil
	case "darwin", "freebsd", "openbsd", "netbsd", "dragonfly":
		return loginPath, []string{"-fp", "-h", addrPort.Addr().String(), username}, nil
	default:
		return "", nil, fmt.Errorf("unsupported Unix platform for login command: %s", runtime.GOOS)
	}
}

// getLinuxLoginCmd returns the login command for Linux systems.
// Handles differences between util-linux and shadow-utils login implementations.
func (s *Server) getLinuxLoginCmd(loginPath, username, remoteIP string) (string, []string) {
	// Special handling for Arch Linux without /etc/pam.d/remote
	var loginArgs []string
	if s.fileExists("/etc/arch-release") && !s.fileExists("/etc/pam.d/remote") {
		loginArgs = []string{"-f", username, "-p"}
	} else {
		loginArgs = []string{"-f", username, "-h", remoteIP, "-p"}
	}

	// util-linux login requires setsid -c to create a new session and set the
	// controlling terminal. Without this, vhangup() kills the parent process.
	// See https://bugs.debian.org/1078023 for details.
	// TODO: handle this via the executor using syscall.Setsid() + TIOCSCTTY + syscall.Exec()
	// to avoid external setsid dependency.
	if !s.loginIsUtilLinux {
		return loginPath, loginArgs
	}

	setsidPath, err := exec.LookPath("setsid")
	if err != nil {
		log.Warnf("setsid not available but util-linux login detected, login may fail: %v", err)
		return loginPath, loginArgs
	}

	args := append([]string{"-w", "-c", loginPath}, loginArgs...)
	return setsidPath, args
}

// fileExists checks if a file exists
func (s *Server) fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// parseUserCredentials extracts numeric UID, GID, and supplementary groups
func (s *Server) parseUserCredentials(localUser *user.User) (uint32, uint32, []uint32, error) {
	uid64, err := strconv.ParseUint(localUser.Uid, 10, 32)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("invalid UID %s: %w", localUser.Uid, err)
	}
	uid := uint32(uid64)

	gid64, err := strconv.ParseUint(localUser.Gid, 10, 32)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("invalid GID %s: %w", localUser.Gid, err)
	}
	gid := uint32(gid64)

	groups, err := s.getSupplementaryGroups(localUser.Username)
	if err != nil {
		log.Warnf("failed to get supplementary groups for user %s: %v", localUser.Username, err)
		groups = []uint32{gid}
	}

	return uid, gid, groups, nil
}

// getSupplementaryGroups retrieves supplementary group IDs for a user
func (s *Server) getSupplementaryGroups(username string) ([]uint32, error) {
	u, err := user.Lookup(username)
	if err != nil {
		return nil, fmt.Errorf("lookup user %s: %w", username, err)
	}

	groupIDStrings, err := u.GroupIds()
	if err != nil {
		return nil, fmt.Errorf("get group IDs for user %s: %w", username, err)
	}

	groups := make([]uint32, len(groupIDStrings))
	for i, gidStr := range groupIDStrings {
		gid64, err := strconv.ParseUint(gidStr, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid group ID %s for user %s: %w", gidStr, username, err)
		}
		groups[i] = uint32(gid64)
	}

	return groups, nil
}

// createExecutorCommand creates a command that spawns netbird ssh exec for privilege dropping.
// Returns the command and a cleanup function (no-op on Unix).
func (s *Server) createExecutorCommand(logger *log.Entry, session ssh.Session, localUser *user.User, hasPty bool) (*exec.Cmd, func(), error) {
	logger.Debugf("creating executor command for user %s (Pty: %v)", localUser.Username, hasPty)

	if err := validateUsername(localUser.Username); err != nil {
		return nil, nil, fmt.Errorf("invalid username %q: %w", localUser.Username, err)
	}

	uid, gid, groups, err := s.parseUserCredentials(localUser)
	if err != nil {
		return nil, nil, fmt.Errorf("parse user credentials: %w", err)
	}
	privilegeDropper := NewPrivilegeDropper(WithLogger(logger))
	config := ExecutorConfig{
		UID:        uid,
		GID:        gid,
		Groups:     groups,
		WorkingDir: localUser.HomeDir,
		Shell:      getUserShell(localUser.Uid),
		Command:    session.RawCommand(),
		PTY:        hasPty,
	}

	cmd, err := privilegeDropper.CreateExecutorCommand(session.Context(), config)
	return cmd, func() {}, err
}

// enableUserSwitching is a no-op on Unix systems
func enableUserSwitching() error {
	return nil
}

// createPtyCommand creates the exec.Cmd for Pty execution respecting privilege check results
func (s *Server) createPtyCommand(privilegeResult PrivilegeCheckResult, ptyReq ssh.Pty, session ssh.Session) (*exec.Cmd, error) {
	localUser := privilegeResult.User
	if localUser == nil {
		return nil, errors.New("no user in privilege result")
	}

	if privilegeResult.UsedFallback {
		return s.createDirectPtyCommand(session, localUser, ptyReq), nil
	}

	return s.createPtyLoginCommand(localUser, ptyReq, session)
}

// createDirectPtyCommand creates a direct Pty command without privilege dropping
func (s *Server) createDirectPtyCommand(session ssh.Session, localUser *user.User, ptyReq ssh.Pty) *exec.Cmd {
	log.Debugf("creating direct Pty command for user %s (no user switching needed)", localUser.Username)

	shell := getUserShell(localUser.Uid)
	args := s.getShellCommandArgs(shell, session.RawCommand())

	cmd := s.createShellCommand(session.Context(), shell, args)
	cmd.Dir = localUser.HomeDir
	cmd.Env = s.preparePtyEnv(localUser, ptyReq, session)

	return cmd
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
