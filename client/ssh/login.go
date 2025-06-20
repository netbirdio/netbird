package ssh

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"runtime"

	"github.com/netbirdio/netbird/util"
)

func isRoot() bool {
	return os.Geteuid() == 0
}

func getLoginCmd(username string, remoteAddr net.Addr) (loginPath string, args []string, err error) {
	// First, validate the user exists
	if err := validateUser(username); err != nil {
		return "", nil, err
	}

	if runtime.GOOS == "windows" {
		return getWindowsLoginCmd(username)
	}

	if !isRoot() {
		return getNonRootLoginCmd(username)
	}

	return getRootLoginCmd(username, remoteAddr)
}

// validateUser checks if the requested user exists and is valid
func validateUser(username string) error {
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}

	// Check if user exists
	if _, err := userNameLookup(username); err != nil {
		return fmt.Errorf("user %s not found: %w", username, err)
	}

	return nil
}

// getWindowsLoginCmd handles Windows login (currently limited)
func getWindowsLoginCmd(username string) (string, []string, error) {
	currentUser, err := user.Current()
	if err != nil {
		return "", nil, fmt.Errorf("get current user: %w", err)
	}

	// Check if requesting a different user
	if currentUser.Username != username {
		// TODO: Implement Windows user impersonation using CreateProcessAsUser
		return "", nil, fmt.Errorf("Windows user switching not implemented: cannot switch from %s to %s", currentUser.Username, username)
	}

	shell := getUserShell(currentUser.Uid)
	return shell, []string{}, nil
}

// getNonRootLoginCmd handles non-root process login
func getNonRootLoginCmd(username string) (string, []string, error) {
	// Non-root processes can only SSH as themselves
	currentUser, err := user.Current()
	if err != nil {
		return "", nil, fmt.Errorf("get current user: %w", err)
	}

	if username != "" && currentUser.Username != username {
		return "", nil, fmt.Errorf("non-root process cannot switch users: requested %s but running as %s", username, currentUser.Username)
	}

	shell := getUserShell(currentUser.Uid)
	return shell, []string{"-l"}, nil
}

// getRootLoginCmd handles root-privileged login with user switching
func getRootLoginCmd(username string, remoteAddr net.Addr) (string, []string, error) {
	// Require login command to be available
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
		if util.FileExists("/etc/arch-release") && !util.FileExists("/etc/pam.d/remote") {
			return loginPath, []string{"-f", username, "-p"}, nil
		}
		return loginPath, []string{"-f", username, "-h", addrPort.Addr().String(), "-p"}, nil
	case "darwin", "freebsd", "openbsd", "netbsd", "dragonfly":
		return loginPath, []string{"-fp", "-h", addrPort.Addr().String(), username}, nil
	default:
		return "", nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}
