package posture

import (
	"strings"

	"github.com/hashicorp/go-version"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	log "github.com/sirupsen/logrus"
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

func (c *OSVersionCheck) Check(peer nbpeer.Peer) (bool, error) {
	peerGoOS := peer.Meta.GoOS
	switch peerGoOS {
	case "android":
		return checkMinVersion(peerGoOS, peer.Meta.OSVersion, c.Android)
	case "darwin":
		return checkMinVersion(peerGoOS, peer.Meta.OSVersion, c.Darwin)
	case "ios":
		return checkMinVersion(peerGoOS, peer.Meta.OSVersion, c.Ios)
	case "linux":
		kernelVersion := strings.Split(peer.Meta.KernelVersion, "-")[0]
		return checkMinKernelVersion(peerGoOS, kernelVersion, c.Linux)
	case "windows":
		return checkMinKernelVersion(peerGoOS, peer.Meta.KernelVersion, c.Windows)
	}
	return true, nil
}

func (c *OSVersionCheck) Name() string {
	return OSVersionCheckName
}

func checkMinVersion(peerGoOS, peerVersion string, check *MinVersionCheck) (bool, error) {
	if check == nil {
		log.Debugf("peer %s OS is not allowed in the check", peerGoOS)
		return false, nil
	}

	peerNBVersion, err := version.NewVersion(peerVersion)
	if err != nil {
		return false, err
	}

	constraints, err := version.NewConstraint(">= " + check.MinVersion)
	if err != nil {
		return false, err
	}

	if constraints.Check(peerNBVersion) {
		return true, nil
	}

	log.Debugf("peer %s OS version %s is older than minimum allowed version %s", peerGoOS, peerVersion, check.MinVersion)

	return false, nil
}

func checkMinKernelVersion(peerGoOS, peerVersion string, check *MinKernelVersionCheck) (bool, error) {
	if check == nil {
		log.Debugf("peer %s OS is not allowed in the check", peerGoOS)
		return false, nil
	}

	peerNBVersion, err := version.NewVersion(peerVersion)
	if err != nil {
		return false, err
	}

	constraints, err := version.NewConstraint(">= " + check.MinKernelVersion)
	if err != nil {
		return false, err
	}

	if constraints.Check(peerNBVersion) {
		return true, nil
	}

	log.Debugf("peer %s kernel version %s is older than minimum allowed version %s", peerGoOS, peerVersion, check.MinKernelVersion)

	return false, nil
}
