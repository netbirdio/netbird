package device

import (
	"os"

	"github.com/netbirdio/netbird/client/iface/wgbackend"
)

func wgLogLevel() int {
	if os.Getenv("NB_WG_DEBUG") == "true" {
		return wgbackend.LogLevelVerbose
	} else {
		return wgbackend.LogLevelSilent
	}
}
