package posture

import (
	"context"
	"fmt"
	"slices"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

type Process struct {
	LinuxPath   string
	MacPath     string
	WindowsPath string
}

type ProcessCheck struct {
	Processes []Process
}

var _ Check = (*ProcessCheck)(nil)

func (p *ProcessCheck) Check(_ context.Context, peer nbpeer.Peer) (bool, error) {
	peerActiveProcesses := extractPeerActiveProcesses(peer.Meta.Files)

	var pathSelector func(Process) string
	switch peer.Meta.GoOS {
	case "linux":
		pathSelector = func(process Process) string { return process.LinuxPath }
	case "darwin":
		pathSelector = func(process Process) string { return process.MacPath }
	case "windows":
		pathSelector = func(process Process) string { return process.WindowsPath }
	default:
		return false, fmt.Errorf("unsupported peer's operating system: %s", peer.Meta.GoOS)
	}

	return p.areAllProcessesRunning(peerActiveProcesses, pathSelector), nil
}

func (p *ProcessCheck) Name() string {
	return ProcessCheckName
}

func (p *ProcessCheck) Validate() error {
	if len(p.Processes) == 0 {
		return fmt.Errorf("%s processes shouldn't be empty", p.Name())
	}

	for _, process := range p.Processes {
		if process.LinuxPath == "" && process.MacPath == "" && process.WindowsPath == "" {
			return fmt.Errorf("%s path shouldn't be empty", p.Name())
		}
	}
	return nil
}

// areAllProcessesRunning checks if all processes specified in ProcessCheck are running.
// It uses the provided pathSelector to get the appropriate process path for the peer's OS.
// It returns true if all processes are running, otherwise false.
func (p *ProcessCheck) areAllProcessesRunning(activeProcesses []string, pathSelector func(Process) string) bool {
	for _, process := range p.Processes {
		path := pathSelector(process)
		if path == "" || !slices.Contains(activeProcesses, path) {
			return false
		}
	}
	return true
}

// extractPeerActiveProcesses extracts the paths of running processes from the peer meta.
func extractPeerActiveProcesses(files []nbpeer.File) []string {
	activeProcesses := make([]string, 0, len(files))
	for _, file := range files {
		if file.ProcessIsRunning {
			activeProcesses = append(activeProcesses, file.Path)
		}
	}
	return activeProcesses
}
