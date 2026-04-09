package portforward

import (
	"os"
	"strconv"

	log "github.com/sirupsen/logrus"
)

const (
	envDisableNATMapper = "NB_DISABLE_NAT_MAPPER"
)

func isDisabledByEnv() bool {
	val := os.Getenv(envDisableNATMapper)
	if val == "" {
		return false
	}

	disabled, err := strconv.ParseBool(val)
	if err != nil {
		log.Warnf("failed to parse %s: %v", envDisableNATMapper, err)
		return false
	}
	return disabled
}
