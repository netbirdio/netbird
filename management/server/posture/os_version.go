package posture

import (
	"fmt"

	"github.com/hashicorp/go-version"
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
		return checkMinVersion(peerGoOS, peer.Meta.Core, c.Linux)
	case "windows":
		return checkMinVersion(peerGoOS, peer.Meta.Core, c.Windows)
	}
	return nil
}

func (c *OSVersionCheck) Name() string {
	return OSVersionCheckName
}

func checkMinVersion(peerGoOS, peerVersion string, check *MinVersionCheck) error {
	if check == nil {
		return nil
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

	return fmt.Errorf("peer %s version %s is older than minimum allowed version %s", peerGoOS, peerVersion, check.MinVersion)
}
