//go:build windows

package cmd

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// isProcessPrivileged reports whether the current process token is elevated
// (running as administrator / LocalSystem).
func isProcessPrivileged() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// runElevated should re-run exe with args elevated via a UAC prompt
// (ShellExecuteEx with the "runas" verb).
//
// TODO(ssh-elevation): implement ShellExecuteEx("runas") + wait for the child.
func runElevated(_ string, _ []string) error {
	return fmt.Errorf("automatic privilege elevation is not yet implemented on Windows, re-run netbird as administrator")
}
