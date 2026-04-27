package peer

import (
	"os"
	"runtime"
	"strings"
)

const (
	EnvKeyNBForceRelay = "NB_FORCE_RELAY"
)

func IsForceRelayed() bool {
	if runtime.GOOS == "js" {
		return true
	}
	return strings.EqualFold(os.Getenv(EnvKeyNBForceRelay), "true")
}
