package nmdata

import (
	"strings"

	"github.com/hashicorp/go-version"
)

// MinVersionCheck is the slim twin of posture.MinVersionCheck.
type MinVersionCheck struct {
	MinVersion string
}

// MinKernelVersionCheck is the slim twin of posture.MinKernelVersionCheck.
type MinKernelVersionCheck struct {
	MinKernelVersion string
}

// OSVersionCheck is the slim twin of posture.OSVersionCheck.
type OSVersionCheck struct {
	Android *MinVersionCheck
	Darwin  *MinVersionCheck
	Ios     *MinVersionCheck
	Linux   *MinKernelVersionCheck
	Windows *MinKernelVersionCheck
}

func (c *OSVersionCheck) check(peer *Peer) (bool, error) {
	switch peer.Meta.GoOS {
	case "android":
		return checkMinVersion(peer.Meta.OSVersion, c.Android)
	case "darwin":
		return checkMinVersion(peer.Meta.OSVersion, c.Darwin)
	case "ios":
		return checkMinVersion(peer.Meta.OSVersion, c.Ios)
	case "linux":
		kernelVersion := strings.Split(peer.Meta.KernelVersion, "-")[0]
		return checkMinKernelVersion(kernelVersion, c.Linux)
	case "windows":
		return checkMinKernelVersion(peer.Meta.KernelVersion, c.Windows)
	}
	return true, nil
}

func checkMinVersion(peerVersion string, check *MinVersionCheck) (bool, error) {
	if check == nil {
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

	return constraints.Check(peerNBVersion), nil
}

func checkMinKernelVersion(peerVersion string, check *MinKernelVersionCheck) (bool, error) {
	if check == nil {
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

	return constraints.Check(peerNBVersion), nil
}
