//go:build windows

package main

import (
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"

	nbprocess "github.com/netbirdio/netbird/client/ui/process"
)

// killParentUIProcess finds and kills the parent systray UI process on Windows.
// This is a workaround in case the MSI installer fails to properly terminate the UI process.
// The installer should handle this via util:CloseApplication with TerminateProcess, but this
// provides an additional safety mechanism to ensure the UI is closed before the upgrade proceeds.
func killParentUIProcess() {
	pid, running, err := nbprocess.IsAnotherProcessRunning()
	if err != nil {
		log.Warnf("failed to check for parent UI process: %v", err)
		return
	}

	if !running {
		log.Debug("no parent UI process found to kill")
		return
	}

	log.Infof("killing parent UI process (PID: %d)", pid)

	// Open the process with terminate rights
	handle, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		log.Warnf("failed to open parent process %d: %v", pid, err)
		return
	}
	defer func() {
		_ = windows.CloseHandle(handle)
	}()

	// Terminate the process with exit code 0
	if err := windows.TerminateProcess(handle, 0); err != nil {
		log.Warnf("failed to terminate parent process %d: %v", pid, err)
	}
}
