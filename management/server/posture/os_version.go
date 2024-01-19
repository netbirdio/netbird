package posture

import (
	"fmt"

	"github.com/hashicorp/go-version"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

type MinVersionCheck struct {
	MinVersion string
}

type MinKernelVersionCheck struct {
	MinKernelVersion string
}

type OSVersionCheck struct {
	Android *MinVersionCheck
	Darwin  *MinVersionCheck
	Ios     *MinVersionCheck
	Linux   *MinKernelVersionCheck
	Windows *MinKernelVersionCheck
}

var _ Check = (*OSVersionCheck)(nil)

func (c *OSVersionCheck) Check(peer nbpeer.Peer) error {
	peerGoOS := peer.Meta.GoOS
	switch peerGoOS {
	case "android":
		return checkMinVersion(peerGoOS, peer.Meta.Core, c.Android)
	case "darwin":
		return checkMinVersion(peerGoOS, peer.Meta.Core, c.Darwin)
	case "ios":
		return checkMinVersion(peerGoOS, peer.Meta.Core, c.Ios)
	case "linux":
		return checkMinKernelVersion(peerGoOS, peer.Meta.KernelVersion, c.Linux)
	case "windows":
		return checkMinKernelVersion(peerGoOS, peer.Meta.KernelVersion, c.Windows)
	}
	return nil
}

func (c *OSVersionCheck) Name() string {
	return OSVersionCheckName
}

func checkMinVersion(peerGoOS, peerVersion string, check *MinVersionCheck) error {
	if check == nil {
		return fmt.Errorf("peer %s OS is not allowed", peerGoOS)
	}

	peerNBVersion, err := version.NewVersion(peerVersion)
	if err != nil {
		return err
	}

	constraints, err := version.NewConstraint(">= " + check.MinVersion)
	if err != nil {
		return err
	}

	if constraints.Check(peerNBVersion) {
		return nil
	}

	return fmt.Errorf("peer %s OS version %s is older than minimum allowed version %s", peerGoOS, peerVersion, check.MinVersion)
}

func checkMinKernelVersion(peerGoOS, peerVersion string, check *MinKernelVersionCheck) error {
	if check == nil {
		return fmt.Errorf("peer %s OS is not allowed", peerGoOS)
	}

	peerNBVersion, err := version.NewVersion(peerVersion)
	if err != nil {
		return err
	}

	constraints, err := version.NewConstraint(">= " + check.MinKernelVersion)
	if err != nil {
		return err
	}

	if constraints.Check(peerNBVersion) {
		return nil
	}

	return fmt.Errorf("peer %s kernel version %s is older than minimum allowed version %s", peerGoOS, peerVersion, check.MinKernelVersion)
}
