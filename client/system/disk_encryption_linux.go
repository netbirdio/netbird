//go:build linux && !android

package system

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
)

// detectDiskEncryption detects LUKS encryption status on Linux by reading sysfs.
func detectDiskEncryption(ctx context.Context) DiskEncryptionInfo {
	info := DiskEncryptionInfo{}

	encryptedDevices := findEncryptedDevices()
	mountPoints := parseMounts(encryptedDevices)

	info.Volumes = mountPoints
	return info
}

// findEncryptedDevices scans /sys/block for dm-crypt (LUKS) encrypted devices.
func findEncryptedDevices() map[string]bool {
	encryptedDevices := make(map[string]bool)

	sysBlock := "/sys/block"
	entries, err := os.ReadDir(sysBlock)
	if err != nil {
		log.Debugf("read /sys/block: %v", err)
		return encryptedDevices
	}

	for _, entry := range entries {
		dmUuidPath := filepath.Join(sysBlock, entry.Name(), "dm", "uuid")
		data, err := os.ReadFile(dmUuidPath)
		if err != nil {
			continue
		}
		uuid := strings.TrimSpace(string(data))
		if strings.HasPrefix(uuid, "CRYPT-") {
			dmNamePath := filepath.Join(sysBlock, entry.Name(), "dm", "name")
			if nameData, err := os.ReadFile(dmNamePath); err == nil {
				dmName := strings.TrimSpace(string(nameData))
				encryptedDevices["/dev/mapper/"+dmName] = true
			}
			encryptedDevices["/dev/"+entry.Name()] = true
		}
	}

	return encryptedDevices
}

// parseMounts reads /proc/mounts and maps devices to mount points with encryption status.
func parseMounts(encryptedDevices map[string]bool) []DiskEncryptionVolume {
	var volumes []DiskEncryptionVolume

	mountsFile, err := os.Open("/proc/mounts")
	if err != nil {
		log.Debugf("open /proc/mounts: %v", err)
		return volumes
	}
	defer func() {
		if err := mountsFile.Close(); err != nil {
			log.Debugf("close /proc/mounts: %v", err)
		}
	}()

	scanner := bufio.NewScanner(mountsFile)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		device, mountPoint := fields[0], fields[1]

		encrypted := encryptedDevices[device]

		if !encrypted && strings.HasPrefix(device, "/dev/mapper/") {
			for encDev := range encryptedDevices {
				if device == encDev {
					encrypted = true
					break
				}
			}
		}

		volumes = append(volumes, DiskEncryptionVolume{
			Path:      mountPoint,
			Encrypted: encrypted,
		})
	}

	return volumes
}
