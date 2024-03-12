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
	peerActiveProcesses := make([]string, 0, len(peer.Meta.Processes))
	for _, process := range peer.Meta.Processes {
		peerActiveProcesses = append(peerActiveProcesses, process.Path)
	}

	switch peer.Meta.GoOS {
	case "darwin", "linux":
		for _, process := range p.Processes {
			if !slices.Contains(peerActiveProcesses, process.Path) {
				return false, nil
			}
		}
		return true, nil
	case "windows":
		for _, process := range p.Processes {
			if !slices.Contains(peerActiveProcesses, process.WindowsPath) {
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
