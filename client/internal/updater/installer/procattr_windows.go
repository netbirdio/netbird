package installer

import (
	"os/exec"
	"syscall"
)

// setUpdaterProcAttr configures the updater process to run detached from the parent,
// making it independent of the parent daemon process.
func setUpdaterProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | 0x00000008, // 0x00000008 is DETACHED_PROCESS
	}
}
