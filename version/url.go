package version

import (
	"os/exec"
	"runtime"
)

const (
	downloadURL = "https://app.netbird.io/install"
	macIntelURL = "https://pkgs.netbird.io/macos/amd64"
	macM1M2URL  = "https://pkgs.netbird.io/macos/arm64"
)

// DownloadUrl return with the proper download link
func DownloadUrl() string {
	switch runtime.GOOS {
	case "windows":
		return downloadURL
	case "darwin":
		return darwinDownloadUrl()
	case "linux":
		return downloadURL
	default:
		return downloadURL
	}
}

func darwinDownloadUrl() string {
	cmd := exec.Command("brew", "list --formula | grep -i netbird")
	if err := cmd.Start(); err != nil {
		goto PKGINSTALL
	}

	if err := cmd.Wait(); err == nil {
		return downloadURL
	}

PKGINSTALL:
	switch runtime.GOARCH {
	case "amd64":
		return macIntelURL
	case "arm64":
		return macM1M2URL
	default:
		return downloadURL
	}
}
