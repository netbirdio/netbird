package version

import (
	"os/exec"
	"runtime"
)

const (
	urlMacIntel = "https://pkgs.netbird.io/macos/amd64"
	urlMacM1M2  = "https://pkgs.netbird.io/macos/arm64"
)

// DownloadUrl return with the proper download link
func DownloadUrl() string {
	if isBrewInstall() {
		return downloadURL
	}

	switch runtime.GOARCH {
	case "amd64":
		return urlMacIntel
	case "arm64":
		return urlMacM1M2
	default:
		return downloadURL
	}
}

// isBrewInstall reports whether NetBird is installed via Homebrew, either as
// the netbird formula or the netbird-ui cask.
func isBrewInstall() bool {
	if err := exec.Command("brew", "list", "--formula", "netbird").Run(); err == nil {
		return true
	}
	return exec.Command("brew", "list", "--cask", "netbird-ui").Run() == nil
}
