package client

import (
	"os"
	"strconv"
)

const (
	envKeyNBDebugDisableRelay = "NB_DEBUG_DISABLE_RELAY"
)

func IsDisableRelay() bool {
	v, _ := strconv.ParseBool(os.Getenv(envKeyNBDebugDisableRelay))
	return v
}
