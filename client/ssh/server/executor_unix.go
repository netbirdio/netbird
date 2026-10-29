//go:build unix

package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

// Exit codes for executor process communication
const (
	ExitCodeSuccess            = 0
	ExitCodePrivilegeDropFail  = 10
	ExitCodeShellExecFail      = 11
	ExitCodeValidationFail     = 12
	ExitCodeSELinuxContextFail = 13
)

// ExecutorConfig holds configuration for the executor process
type ExecutorConfig struct {
	// Username is the login name of the target user, used to resolve the SELinux context
	// the session starts in.
	Username   string
	UID        uint32
	GID        uint32
	Groups     []uint32
	WorkingDir string
	Shell      string
	Command    string
	PTY        bool
}

// PrivilegeDropper handles secure privilege dropping in child processes
type PrivilegeDropper struct {
	logger *log.Entry
}

// PrivilegeDropperOption is a functional option for configuring PrivilegeDropper
type PrivilegeDropperOption func(*PrivilegeDropper)

// NewPrivilegeDropper creates a new privilege dropper
func NewPrivilegeDropper(opts ...PrivilegeDropperOption) *PrivilegeDropper {
	pd := &PrivilegeDropper{}
	for _, opt := range opts {
		opt(pd)
	}
	return pd
}

// WithLogger sets the logger for the PrivilegeDropper
func WithLogger(logger *log.Entry) PrivilegeDropperOption {
	return func(pd *PrivilegeDropper) {
		pd.logger = logger
	}
}

// log returns the logger, falling back to standard logger if none set
func (pd *PrivilegeDropper) log() *log.Entry {
	if pd.logger != nil {
		return pd.logger
	}
	return log.NewEntry(log.StandardLogger())
}

// CreateExecutorCommand creates a command that spawns netbird ssh exec for privilege dropping
func (pd *PrivilegeDropper) CreateExecutorCommand(ctx context.Context, config ExecutorConfig) (*exec.Cmd, error) {
	netbirdPath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("get netbird executable path: %w", err)
	}

	if err := pd.validatePrivileges(config.UID, config.GID); err != nil {
		return nil, fmt.Errorf("invalid privileges: %w", err)
	}

	args := []string{
		"ssh", "exec",
		"--user", config.Username,
		"--uid", fmt.Sprintf("%d", config.UID),
		"--gid", fmt.Sprintf("%d", config.GID),
		"--working-dir", config.WorkingDir,
		"--shell", config.Shell,
	}

	for _, group := range config.Groups {
		args = append(args, "--groups", fmt.Sprintf("%d", group))
	}

	if config.PTY {
		args = append(args, "--pty")
	}

	if config.Command != "" {
		args = append(args, "--cmd", config.Command)
	}

	// Log executor args safely - show all args except hide the command value
	safeArgs := make([]string, len(args))
	copy(safeArgs, args)
	for i := 0; i < len(safeArgs)-1; i++ {
		if safeArgs[i] == "--cmd" {
			cmdParts := strings.Fields(safeArgs[i+1])
			safeArgs[i+1] = safeLogCommand(cmdParts)
			break
		}
	}
	pd.log().Tracef("creating executor command: %s %v", netbirdPath, safeArgs)
	return exec.CommandContext(ctx, netbirdPath, args...), nil
}

// DropPrivileges performs privilege dropping with thread locking for security
func (pd *PrivilegeDropper) DropPrivileges(targetUID, targetGID uint32, supplementaryGroups []uint32) error {
	if err := pd.validatePrivileges(targetUID, targetGID); err != nil {
		return fmt.Errorf("invalid privileges: %w", err)
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	originalUID := os.Geteuid()
	originalGID := os.Getegid()

	if originalUID != int(targetUID) || originalGID != int(targetGID) {
		if err := pd.setGroupsAndIDs(targetUID, targetGID, supplementaryGroups); err != nil {
			return fmt.Errorf("set groups and IDs: %w", err)
		}
	}

	if err := pd.validatePrivilegeDropSuccess(targetUID, targetGID, originalUID, originalGID); err != nil {
		return err
	}

	log.Tracef("successfully dropped privileges to UID=%d, GID=%d", targetUID, targetGID)
	return nil
}

// setGroupsAndIDs sets the supplementary groups, GID, and UID
func (pd *PrivilegeDropper) setGroupsAndIDs(targetUID, targetGID uint32, supplementaryGroups []uint32) error {
	groups := make([]int, len(supplementaryGroups))
	for i, g := range supplementaryGroups {
		groups[i] = int(g)
	}

	if runtime.GOOS == "darwin" || runtime.GOOS == "freebsd" {
		if len(groups) == 0 || groups[0] != int(targetGID) {
			groups = append([]int{int(targetGID)}, groups...)
		}
	}

	if err := setgroups(groups); err != nil {
		return fmt.Errorf("setgroups to %v: %w", groups, err)
	}

	if err := setgid(int(targetGID)); err != nil {
		return fmt.Errorf("setgid to %d: %w", targetGID, err)
	}

	if err := setuid(int(targetUID)); err != nil {
		return fmt.Errorf("setuid to %d: %w", targetUID, err)
	}

	return nil
}

// validatePrivilegeDropSuccess validates that privilege dropping was successful
func (pd *PrivilegeDropper) validatePrivilegeDropSuccess(targetUID, targetGID uint32, originalUID, originalGID int) error {
	if err := pd.validatePrivilegeDropReversibility(targetUID, targetGID, originalUID, originalGID); err != nil {
		return err
	}

	if err := pd.validateCurrentPrivileges(targetUID, targetGID); err != nil {
		return err
	}

	return nil
}

// validatePrivilegeDropReversibility ensures privileges cannot be restored
func (pd *PrivilegeDropper) validatePrivilegeDropReversibility(targetUID, targetGID uint32, originalUID, originalGID int) error {
	if originalGID != int(targetGID) {
		if err := setegid(originalGID); err == nil {
			return fmt.Errorf("privilege drop validation failed: able to restore original GID %d", originalGID)
		}
	}
	if originalUID != int(targetUID) {
		if err := seteuid(originalUID); err == nil {
			return fmt.Errorf("privilege drop validation failed: able to restore original UID %d", originalUID)
		}
	}
	return nil
}

// validateCurrentPrivileges validates the current UID and GID match the target
func (pd *PrivilegeDropper) validateCurrentPrivileges(targetUID, targetGID uint32) error {
	currentUID := os.Geteuid()
	if currentUID != int(targetUID) {
		return fmt.Errorf("privilege drop validation failed: current UID %d, expected %d", currentUID, targetUID)
	}

	currentGID := os.Getegid()
	if currentGID != int(targetGID) {
		return fmt.Errorf("privilege drop validation failed: current GID %d, expected %d", currentGID, targetGID)
	}

	return nil
}

// ExecuteWithPrivilegeDrop executes a command with privilege dropping, using exit codes to signal specific failures
func (pd *PrivilegeDropper) ExecuteWithPrivilegeDrop(ctx context.Context, config ExecutorConfig) {
	log.Tracef("dropping privileges to UID=%d, GID=%d, groups=%v", config.UID, config.GID, config.Groups)

	// TODO: Implement Pty support for executor path
	if config.PTY {
		config.PTY = false
	}

	// The SELinux exec context is per thread, so the thread that sets it must be the one
	// that forks the shell. The process exits afterwards, so the lock is never released.
	runtime.LockOSThread()

	// The context is resolved while still root, and a failure refuses the session rather
	// than starting it in the daemon's own domain.
	sessionContext, err := sessionExecContext(config.Username, groupNames(config.Groups))
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "resolve SELinux session context: %v\n", err)
		os.Exit(ExitCodeSELinuxContextFail)
	}

	if err := pd.DropPrivileges(config.UID, config.GID, config.Groups); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "privilege drop failed: %v\n", err)
		os.Exit(ExitCodePrivilegeDropFail)
	}

	if sessionContext != "" {
		log.Tracef("starting session in SELinux context %s", sessionContext)
		if err := setExecContext(sessionContext); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "set SELinux session context: %v\n", err)
			os.Exit(ExitCodeSELinuxContextFail)
		}
	}

	if config.WorkingDir != "" {
		if err := os.Chdir(config.WorkingDir); err != nil {
			log.Debugf("failed to change to working directory %s, continuing with current directory: %v", config.WorkingDir, err)
		}
	}

	var execCmd *exec.Cmd
	if config.Command == "" {
		execCmd = exec.CommandContext(ctx, config.Shell)
	} else {
		execCmd = exec.CommandContext(ctx, config.Shell, "-c", config.Command)
	}
	execCmd.Args[0] = "-" + filepath.Base(config.Shell)
	execCmd.Stdin = os.Stdin
	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr

	if config.Command == "" {
		log.Tracef("executing login shell: %s", execCmd.Path)
	} else {
		cmdParts := strings.Fields(config.Command)
		safeCmd := safeLogCommand(cmdParts)
		log.Tracef("executing %s -c %s", execCmd.Path, safeCmd)
	}
	if err := execCmd.Run(); err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			// Normal command exit with non-zero code - not an SSH execution error
			log.Tracef("command exited with code %d", exitError.ExitCode())
			os.Exit(exitError.ExitCode())
		}

		// Actual execution failure (command not found, permission denied, etc.)
		log.Debugf("command execution failed: %v", err)
		os.Exit(ExitCodeShellExecFail)
	}

	os.Exit(ExitCodeSuccess)
}

// groupNames resolves group IDs to names, skipping the ones that cannot be resolved.
func groupNames(gids []uint32) []string {
	names := make([]string, 0, len(gids))
	for _, gid := range gids {
		if g, err := user.LookupGroupId(strconv.FormatUint(uint64(gid), 10)); err == nil {
			names = append(names, g.Name)
		}
	}
	return names
}

// validatePrivileges validates that privilege dropping to the target UID/GID is allowed
func (pd *PrivilegeDropper) validatePrivileges(uid, gid uint32) error {
	currentUID := uint32(os.Geteuid())
	currentGID := uint32(os.Getegid())

	// Allow same-user operations (no privilege dropping needed)
	if uid == currentUID && gid == currentGID {
		return nil
	}

	// Only root can drop privileges to other users
	if currentUID != 0 {
		return fmt.Errorf("cannot drop privileges from non-root user (UID %d) to UID %d", currentUID, uid)
	}

	// Root can drop to any user (including root itself)
	return nil
}
