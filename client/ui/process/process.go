package process

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/shirou/gopsutil/v3/process"
)

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
		// most errors are related to short-lived processes
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
