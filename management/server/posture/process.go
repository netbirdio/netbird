package posture

import (
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
	return false, nil
}

func (p *ProcessCheck) Name() string {
	return ProcessCheckName
}
