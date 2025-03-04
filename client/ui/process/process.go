package process

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/shirou/gopsutil/v3/process"
)

func IsAnotherProcessRunning() (bool, error) {
	processes, err := process.Processes()
	if err != nil {
		return false, err
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

		if strings.Contains(strings.ToLower(runningProcessPath), processName) && isProcessOwnedByCurrentUser(p) {
			return true, nil
		}
	}

	return false, nil
}
