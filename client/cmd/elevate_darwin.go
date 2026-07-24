//go:build darwin

package cmd

import (
	"fmt"
	"os"
)

// isProcessPrivileged reports whether the current process runs as root.
func isProcessPrivileged() bool { return os.Geteuid() == 0 }

// TODO(ssh-elevation): implement the osascript admin prompt.
func runElevated(_ string, _ []string) error {
	return fmt.Errorf("automatic privilege elevation is not yet implemented on macOS, re-run with sudo")
}
