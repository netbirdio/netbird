//go:build darwin && !ios

package system

import (
	"context"
	"os/exec"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// detectDiskEncryption detects FileVault encryption status on macOS.
func detectDiskEncryption(ctx context.Context) DiskEncryptionInfo {
	info := DiskEncryptionInfo{}

	cmdCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, "fdesetup", "status")
	output, err := cmd.Output()
	if err != nil {
		log.Debugf("execute fdesetup: %v", err)
		return info
	}

	encrypted := strings.Contains(string(output), "FileVault is On")
	info.Volumes = append(info.Volumes, DiskEncryptionVolume{
		Path:      "/",
		Encrypted: encrypted,
	})

	return info
}
