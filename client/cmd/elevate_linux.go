//go:build linux

package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// isProcessPrivileged reports whether the current process runs as root.
func isProcessPrivileged() bool { return os.Geteuid() == 0 }

// runElevated re-runs exe with args as root. On a graphical session it uses
// pkexec, which drives the desktop's polkit authentication agent (GUI prompt).
func runElevated(exe string, args []string) error {
	if !hasGraphicalSession() {
		return fmt.Errorf("cannot request privilege elevation without a graphical session. re-run as root: sudo %s %s", exe, strings.Join(args, " "))
	}
	pkexec, err := exec.LookPath("pkexec")
	if err != nil {
		return fmt.Errorf("pkexec not found for privilege elevation, re-run as root: sudo %s %s", exe, strings.Join(args, " "))
	}

	c := exec.Command(pkexec, append([]string{exe}, args...)...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := c.Run(); err != nil {
		return fmt.Errorf("elevated %s failed (elevation cancelled or denied?): %w", SetSSHConfigCmdName, err)
	}
	return nil
}

// hasGraphicalSession heuristically reports whether a desktop session is present
// that polkit can prompt in.
func hasGraphicalSession() bool {
	return os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
}
