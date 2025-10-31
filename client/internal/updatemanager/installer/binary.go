package installer

import (
	"path/filepath"
	"strings"
)

const (
	daemonName    = "netbird.exe"
	uiName        = "netbird-ui.exe"
	updaterBinary = "updater.exe"
)

func UpdaterBinaryNameWithoutExtension() string {
	ext := filepath.Ext(updaterBinary)
	return strings.TrimSuffix(updaterBinary, ext)
}
