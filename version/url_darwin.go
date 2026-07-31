package version

import (
	"context"
	"os/exec"
	"runtime"
	"time"
)

const (
	urlMacIntel          = "https://pkgs.netbird.io/macos/amd64"
	urlMacM1M2           = "https://pkgs.netbird.io/macos/arm64"
	homebrewCheckTimeout = 5 * time.Second
)

// DownloadUrl return with the proper download link
func DownloadUrl() string {
	ctx, cancel := context.WithTimeout(context.Background(), homebrewCheckTimeout)
	defer cancel()

	if isHomebrewInstall(ctx) {
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

func isHomebrewInstall(ctx context.Context) bool {
	brew := brewExecutable()
	if brew == "" {
		return false
	}

	if err := exec.CommandContext(ctx, brew, "list", "--formula", "netbird").Run(); err == nil {
		return true
	}

	return exec.CommandContext(ctx, brew, "list", "--cask", "netbird-ui").Run() == nil
}

func brewExecutable() string {
	if brew, err := exec.LookPath("brew"); err == nil {
		return brew
	}

	for _, path := range []string{"/opt/homebrew/bin/brew", "/usr/local/bin/brew"} {
		if brew, err := exec.LookPath(path); err == nil {
			return brew
		}
	}

	return ""
}
