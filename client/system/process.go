//go:build windows || (linux && !android) || (darwin && !ios) || freebsd

package system

import (
	"context"
	"os"
	"slices"

	"github.com/shirou/gopsutil/v3/process"
)

// getRunningProcesses returns a list of running process paths. The context bounds the work:
// the per-PID loop bails as soon as ctx is done, and the gopsutil calls honor it where they
// can, so a stuck enumeration cannot run unbounded.
func getRunningProcesses(ctx context.Context) ([]string, error) {
	processIDs, err := process.PidsWithContext(ctx)
	if err != nil {
		return nil, err
	}

	processMap := make(map[string]bool)
	for _, pID := range processIDs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p := &process.Process{Pid: pID}

		path, _ := p.ExeWithContext(ctx)
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
func checkFileAndProcess(ctx context.Context, paths []string) ([]File, error) {
	files := make([]File, len(paths))
	if len(paths) == 0 {
		return files, nil
	}

	runningProcesses, err := getRunningProcesses(ctx)
	if err != nil {
		return nil, err
	}

	for i, path := range paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		file := File{Path: path}

		_, err := os.Stat(path)
		file.Exist = !os.IsNotExist(err)

		file.ProcessIsRunning = slices.Contains(runningProcesses, path)
		files[i] = file
	}

	return files, nil
}
