package installer

import (
	"os/exec"
	"syscall"
)

// setUpdaterProcAttr configures the updater process to run in a new session,
// making it independent of the parent daemon process. This ensures the updater
// survives when the daemon is stopped during the pkg installation.
func setUpdaterProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}
}
