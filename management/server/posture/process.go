package posture

import (
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

func (p *ProcessCheck) Check(peer nbpeer.Peer) (bool, error) {
	peerActiveProcesses := make([]string, 0, len(peer.Meta.Files))
	for _, file := range peer.Meta.Files {
		if file.ProcessIsRunning {
			peerActiveProcesses = append(peerActiveProcesses, file.Path)
		}
	}

	switch peer.Meta.GoOS {
	case "linux":
		for _, process := range p.Processes {
			if process.LinuxPath == "" || !slices.Contains(peerActiveProcesses, process.LinuxPath) {
				return false, nil
			}
		}
		return true, nil
	case "darwin":
		for _, process := range p.Processes {
			if process.MacPath == "" || !slices.Contains(peerActiveProcesses, process.MacPath) {
				return false, nil
			}
		}
		return true, nil
	case "windows":
		for _, process := range p.Processes {
			if process.WindowsPath == "" || !slices.Contains(peerActiveProcesses, process.WindowsPath) {
				return false, nil
			}
		}
		return true, nil
	default:
		return false, fmt.Errorf("unsupported peer's operating system: %s", peer.Meta.GoOS)
	}
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
