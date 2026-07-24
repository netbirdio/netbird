//go:build !linux && !darwin && !windows

package cmd

import (
	"fmt"
	"os"
	"strings"
)

// isProcessPrivileged reports whether the current process runs as root.
func isProcessPrivileged() bool { return os.Geteuid() == 0 }

// runElevated has no automatic elevation mechanism on these platforms
func runElevated(exe string, args []string) error {
	return fmt.Errorf("automatic privilege elevation is not supported on this platform, re-run as root: sudo %s %s", exe, strings.Join(args, " "))
}
