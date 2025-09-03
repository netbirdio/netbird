//go:build windows || (linux && !android) || (darwin && !ios) || freebsd

package system

import (
	"os"
	"slices"

	"github.com/shirou/gopsutil/v3/process"
)

// getRunningProcesses returns a list of running process paths.
func getRunningProcesses() ([]string, error) {
	processIDs, err := process.Pids()
	if err != nil {
		return nil, err
	}

	processMap := make(map[string]bool)
	for _, pID := range processIDs {
		p := &process.Process{Pid: pID}

		path, _ := p.Exe()
		if path != "" {
			processMap[path] = false
		}
	}

	uniqueProcesses := make([]string, 0, len(processMap))
	for p := range processMap {
		uniqueProcesses = append(uniqueProcesses, p)
	}

	return uniqueProcesses, nil
}

// checkFileAndProcess checks if the file path exists and if a process is running at that path.
func checkFileAndProcess(paths []string) ([]File, error) {
	files := make([]File, len(paths))
	if len(paths) == 0 {
		return files, nil
	}

	runningProcesses, err := getRunningProcesses()
	if err != nil {
		return nil, err
	}

	for i, path := range paths {
		file := File{Path: path}

		_, err := os.Stat(path)
		file.Exist = !os.IsNotExist(err)

		file.ProcessIsRunning = slices.Contains(runningProcesses, path)
		files[i] = file
	}

	return files, nil
}
