package posture

import (
	"fmt"
	"slices"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

type Process struct {
	Path        string
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
	case "darwin", "linux":
		for _, process := range p.Processes {
			if process.Path == "" || !slices.Contains(peerActiveProcesses, process.Path) {
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
		if process.Path == "" && process.WindowsPath == "" {
			return fmt.Errorf("%s path shouldn't be empty", p.Name())
		}
	}
	return nil
}
