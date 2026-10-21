package device

import (
	"os"

	"github.com/netbirdio/wireguard-go/device"
)

func wgLogLevel() int {
	if os.Getenv("NB_WG_DEBUG") == "true" {
		return device.LogLevelVerbose
	} else {
		return device.LogLevelSilent
	}
}
