package posture

import (
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

type MinVersionCheck struct {
	MinVersion string
}

type OSVersionCheck struct {
	Android *MinVersionCheck
	Darwin  *MinVersionCheck
	Ios     *MinVersionCheck
	Linux   *MinVersionCheck
	Windows *MinVersionCheck
}

var _ Check = (*OSVersionCheck)(nil)

func (n *OSVersionCheck) Check(peer nbpeer.Peer) error {
	return nil
}

func (n *OSVersionCheck) Name() string {
	return OSVersionCheckName
}
