//go:build !windows

package installer

const (
	daemonName    = "netbird"
	uiName        = "netbird-ui"
	updaterBinary = "updater"
)

func UpdaterBinaryNameWithoutExtension() string {
	return updaterBinary
}
