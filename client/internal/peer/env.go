package peer

import (
	"os"
	"strings"
)

const (
	EnvKeyNBForceRelay = "NB_FORCE_RELAY"
)

func isForceRelayed() bool {
	return strings.EqualFold(os.Getenv(EnvKeyNBForceRelay), "true")
}
