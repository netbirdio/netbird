package posture

import (
	"context"
	"fmt"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

// DiskEncryptionCheck verifies that specified volumes are encrypted.
type DiskEncryptionCheck struct {
	LinuxPath   string
	DarwinPath  string
	WindowsPath string
}

var _ Check = (*DiskEncryptionCheck)(nil)

// Name returns the name of the check.
func (d *DiskEncryptionCheck) Name() string {
	return DiskEncryptionCheckName
}

// Check performs the disk encryption verification for the given peer.
func (d *DiskEncryptionCheck) Check(_ context.Context, peer nbpeer.Peer) (bool, error) {
	var pathToCheck string

	switch peer.Meta.GoOS {
	case "linux":
		pathToCheck = d.LinuxPath
	case "darwin":
		pathToCheck = d.DarwinPath
	case "windows":
		pathToCheck = d.WindowsPath
	default:
		return false, nil
	}

	if pathToCheck == "" {
		return true, nil
	}

	return peer.Meta.DiskEncryption.IsEncrypted(pathToCheck), nil
}

// Validate checks the configuration of the disk encryption check.
func (d *DiskEncryptionCheck) Validate() error {
	if d.LinuxPath == "" && d.DarwinPath == "" && d.WindowsPath == "" {
		return fmt.Errorf("%s at least one path must be configured", d.Name())
	}
	return nil
}
