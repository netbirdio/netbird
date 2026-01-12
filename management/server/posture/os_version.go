package posture

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/go-version"
	log "github.com/sirupsen/logrus"

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

func (c *OSVersionCheck) Check(ctx context.Context, peer nbpeer.Peer) (bool, error) {
	peerGoOS := peer.Meta.GoOS
	switch peerGoOS {
	case "android":
		return checkMinVersion(ctx, peerGoOS, peer.Meta.OSVersion, c.Android)
	case "darwin":
		return checkMinVersion(ctx, peerGoOS, peer.Meta.OSVersion, c.Darwin)
	case "ios":
		return checkMinVersion(ctx, peerGoOS, peer.Meta.OSVersion, c.Ios)
	case "linux":
		kernelVersion := strings.Split(peer.Meta.KernelVersion, "-")[0]
		return checkMinKernelVersion(ctx, peerGoOS, kernelVersion, c.Linux)
	case "windows":
		return checkMinKernelVersion(ctx, peerGoOS, peer.Meta.KernelVersion, c.Windows)
	}
	return true, nil
}

func (c *OSVersionCheck) Name() string {
	return OSVersionCheckName
}

func (c *OSVersionCheck) Validate() error {
	if c.Android == nil && c.Darwin == nil && c.Ios == nil && c.Linux == nil && c.Windows == nil {
		return fmt.Errorf("%s at least one OS version check is required", c.Name())
	}

	if c.Android != nil && !isVersionValid(c.Android.MinVersion) {
		return fmt.Errorf("%s android version: %s is not valid", c.Name(), c.Android.MinVersion)
	}

	if c.Ios != nil && !isVersionValid(c.Ios.MinVersion) {
		return fmt.Errorf("%s ios version: %s is not valid", c.Name(), c.Ios.MinVersion)
	}

	if c.Darwin != nil && !isVersionValid(c.Darwin.MinVersion) {
		return fmt.Errorf("%s  darwin version: %s is not valid", c.Name(), c.Darwin.MinVersion)
	}

	if c.Linux != nil && !isVersionValid(c.Linux.MinKernelVersion) {
		return fmt.Errorf("%s  linux kernel version: %s is not valid", c.Name(),
			c.Linux.MinKernelVersion)
	}

	if c.Windows != nil && !isVersionValid(c.Windows.MinKernelVersion) {
		return fmt.Errorf("%s  windows kernel version: %s is not valid", c.Name(),
			c.Windows.MinKernelVersion)
	}
	return nil
}

func checkMinVersion(ctx context.Context, peerGoOS, peerVersion string, check *MinVersionCheck) (bool, error) {
	if check == nil {
		log.WithContext(ctx).Tracef("peer %s OS is not allowed in the check", peerGoOS)
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

	log.WithContext(ctx).Debugf("peer %s OS version %s is older than minimum allowed version %s", peerGoOS, peerVersion, check.MinVersion)

	return false, nil
}

func checkMinKernelVersion(ctx context.Context, peerGoOS, peerVersion string, check *MinKernelVersionCheck) (bool, error) {
	if check == nil {
		log.WithContext(ctx).Tracef("peer %s OS is not allowed in the check", peerGoOS)
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

	log.WithContext(ctx).Debugf("peer %s kernel version %s is older than minimum allowed version %s", peerGoOS, peerVersion, check.MinKernelVersion)

	return false, nil
}
