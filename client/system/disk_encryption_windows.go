//go:build windows

package system

import (
	"context"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/yusufpapurcu/wmi"
)

// Win32EncryptableVolume represents the WMI class for BitLocker status.
type Win32EncryptableVolume struct {
	DriveLetter      string
	ProtectionStatus uint32
}

// detectDiskEncryption detects BitLocker encryption status on Windows via WMI.
func detectDiskEncryption(_ context.Context) DiskEncryptionInfo {
	info := DiskEncryptionInfo{}

	var volumes []Win32EncryptableVolume
	query := "SELECT DriveLetter, ProtectionStatus FROM Win32_EncryptableVolume"

	err := wmi.QueryNamespace(query, &volumes, `root\CIMV2\Security\MicrosoftVolumeEncryption`)
	if err != nil {
		log.Debugf("query BitLocker status: %v", err)
		return info
	}

	for _, vol := range volumes {
		driveLetter := strings.TrimSuffix(vol.DriveLetter, "\\")
		info.Volumes = append(info.Volumes, DiskEncryptionVolume{
			Path:      driveLetter,
			Encrypted: vol.ProtectionStatus == 1,
		})
	}

	return info
}
