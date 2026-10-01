package version

import (
	"golang.org/x/sys/windows/registry"
	"runtime"
)

const (
	urlWinExe    = "https://pkgs.netbird.io/windows/x64"
	urlWinExeArm = "https://pkgs.netbird.io/windows/arm64"
)

var regKeyAppPath = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\Netbird"

// DownloadUrl return with the proper download link
func DownloadUrl() string {
	_, err := registry.OpenKey(registry.LOCAL_MACHINE, regKeyAppPath, registry.QUERY_VALUE)
	if err != nil {
		return downloadURL
	}

	url := urlWinExe
	if runtime.GOARCH == "arm64" {
		url = urlWinExeArm
	}

	return url
}
