package device

import (
	"os"

	"golang.zx2c4.com/wireguard/device"
)

func wgLogLevel() int {
	if os.Getenv("NB_WG_DEBUG") == "true" {
		return device.LogLevelVerbose
	} else {
		return device.LogLevelSilent
	}
}
