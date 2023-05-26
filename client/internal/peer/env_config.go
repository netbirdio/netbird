package peer

import (
	"os"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	envICEKeepAliveIntervalSec   = "NB_ICE_KEEP_ALIVE_INTERVAL_SEC"
	envICEDisconnectedTimeoutSec = "NB_ICE_DISCONNECTED_TIMEOUT_SEC"
	envICEForceRelayConn         = "NB_ICE_FORCE_RELAY_CONN"
)

func iceKeepAlive() time.Duration {
	keepAliveEnv := os.Getenv(envICEKeepAliveIntervalSec)
	if keepAliveEnv == "" {
		return iceKeepAliveDefault
	}

	log.Debugf("setting ICE keep alive interval to %s seconds", keepAliveEnv)
	keepAliveEnvSec, err := strconv.Atoi(keepAliveEnv)
	if err != nil {
		log.Warnf("invalid value %s set for %s, using default %v", keepAliveEnv, envICEKeepAliveIntervalSec, iceKeepAliveDefault)
		return iceKeepAliveDefault
	}

	return time.Duration(keepAliveEnvSec) * time.Second
}

func iceDisconnectedTimeout() time.Duration {
	disconnectedTimeoutEnv := os.Getenv(envICEDisconnectedTimeoutSec)
	if disconnectedTimeoutEnv == "" {
		return iceDisconnectedTimeoutDefault
	}

	log.Debugf("setting ICE disconnected timeout to %s seconds", disconnectedTimeoutEnv)
	disconnectedTimeoutSec, err := strconv.Atoi(disconnectedTimeoutEnv)
	if err != nil {
		log.Warnf("invalid value %s set for %s, using default %v", disconnectedTimeoutEnv, envICEDisconnectedTimeoutSec, iceDisconnectedTimeoutDefault)
		return iceDisconnectedTimeoutDefault
	}

	return time.Duration(disconnectedTimeoutSec) * time.Second
}

func hasICEForceRelayConn() bool {
	disconnectedTimeoutEnv := os.Getenv(envICEForceRelayConn)
	if strings.ToLower(disconnectedTimeoutEnv) == "true" {
		return true
	}
	return false
}
