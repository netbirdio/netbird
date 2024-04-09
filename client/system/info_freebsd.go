package system

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/process"

	"github.com/netbirdio/netbird/client/system/detect_cloud"
	"github.com/netbirdio/netbird/client/system/detect_platform"
	"github.com/netbirdio/netbird/version"
)

// GetInfo retrieves and parses the system information
func GetInfo(ctx context.Context) *Info {
	out := _getInfo()
	for strings.Contains(out, "broken pipe") {
		out = _getInfo()
		time.Sleep(500 * time.Millisecond)
	}
	osStr := strings.Replace(out, "\n", "", -1)
	osStr = strings.Replace(osStr, "\r\n", "", -1)
	osInfo := strings.Split(osStr, " ")

	env := Environment{
		Cloud:    detect_cloud.Detect(ctx),
		Platform: detect_platform.Detect(ctx),
	}

	gio := &Info{Kernel: osInfo[0], Platform: runtime.GOARCH, OS: osInfo[2], GoOS: runtime.GOOS, CPUs: runtime.NumCPU(), KernelVersion: osInfo[1], Environment: env}

	systemHostname, _ := os.Hostname()
	gio.Hostname = extractDeviceName(ctx, systemHostname)
	gio.WiretrusteeVersion = version.NetbirdVersion()
	gio.UIVersion = extractUserAgent(ctx)

	return gio
}

func _getInfo() string {
	cmd := exec.Command("uname", "-sri")
	cmd.Stdin = strings.NewReader("some input")
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		fmt.Println("getInfo:", err)
	}
	return out.String()
}

// getRunningProcesses returns a list of running process paths.
func getRunningProcesses() ([]string, error) {
	processes, err := process.Processes()
	if err != nil {
		return nil, err
	}

	processMap := make(map[string]bool)
	for _, p := range processes {
		path, _ := p.Exe()
		if path != "" {
			processMap[path] = true
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
