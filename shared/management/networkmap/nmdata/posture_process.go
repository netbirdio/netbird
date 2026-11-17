package nmdata

import (
	"fmt"
	"slices"
)

// Process is the slim twin of posture.Process.
type Process struct {
	LinuxPath   string
	MacPath     string
	WindowsPath string
}

// ProcessCheck is the slim twin of posture.ProcessCheck.
type ProcessCheck struct {
	Processes []Process
}

func (p *ProcessCheck) check(peer *Peer) (bool, error) {
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

func (p *ProcessCheck) areAllProcessesRunning(activeProcesses []string, pathSelector func(Process) string) bool {
	for _, process := range p.Processes {
		path := pathSelector(process)
		if path == "" || !slices.Contains(activeProcesses, path) {
			return false
		}
	}
	return true
}

func extractPeerActiveProcesses(files []File) []string {
	activeProcesses := make([]string, 0, len(files))
	for _, file := range files {
		if file.ProcessIsRunning {
			activeProcesses = append(activeProcesses, file.Path)
		}
	}
	return activeProcesses
}
