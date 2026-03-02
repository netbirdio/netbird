package process

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/shirou/gopsutil/v3/process"
)

// IsAnotherProcessRunning returns the PID and true if another instance of the
// same binary is already running for the current OS user.
func IsAnotherProcessRunning() (int32, bool, error) {
	processes, err := process.Processes()
	if err != nil {
		return 0, false, err
	}

	pid := os.Getpid()
	processName := strings.ToLower(filepath.Base(os.Args[0]))

	for _, p := range processes {
		if int(p.Pid) == pid {
			continue
		}

		runningProcessPath, err := p.Exe()
		if err != nil {
			continue
		}

		runningProcessName := strings.ToLower(filepath.Base(runningProcessPath))
		if runningProcessName == processName && isProcessOwnedByCurrentUser(p) {
			return p.Pid, true, nil
		}
	}

	return 0, false, nil
}
