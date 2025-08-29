package ice

import (
	"os"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	envICEForceRelayConn            = "NB_ICE_FORCE_RELAY_CONN"
	envICEKeepAliveIntervalSec      = "NB_ICE_KEEP_ALIVE_INTERVAL_SEC"
	envICEDisconnectedTimeoutSec    = "NB_ICE_DISCONNECTED_TIMEOUT_SEC"
	envICEFailedTimeoutSec          = "NB_ICE_FAILED_TIMEOUT_SEC"
	envICERelayAcceptanceMinWaitSec = "NB_ICE_RELAY_ACCEPTANCE_MIN_WAIT_SEC"

	msgWarnInvalidValue = "invalid value %s set for %s, using default %v"
)

func hasICEForceRelayConn() bool {
	disconnectedTimeoutEnv := os.Getenv(envICEForceRelayConn)
	return strings.ToLower(disconnectedTimeoutEnv) == "true"
}

func iceKeepAlive() time.Duration {
	keepAliveEnv := os.Getenv(envICEKeepAliveIntervalSec)
	if keepAliveEnv == "" {
		return iceKeepAliveDefault
	}

	log.Infof("setting ICE keep alive interval to %s seconds", keepAliveEnv)
	keepAliveEnvSec, err := strconv.Atoi(keepAliveEnv)
	if err != nil {
		log.Warnf(msgWarnInvalidValue, keepAliveEnv, envICEKeepAliveIntervalSec, iceKeepAliveDefault)
		return iceKeepAliveDefault
	}

	return time.Duration(keepAliveEnvSec) * time.Second
}

func iceDisconnectedTimeout() time.Duration {
	disconnectedTimeoutEnv := os.Getenv(envICEDisconnectedTimeoutSec)
	if disconnectedTimeoutEnv == "" {
		return iceDisconnectedTimeoutDefault
	}

	log.Infof("setting ICE disconnected timeout to %s seconds", disconnectedTimeoutEnv)
	disconnectedTimeoutSec, err := strconv.Atoi(disconnectedTimeoutEnv)
	if err != nil {
		log.Warnf(msgWarnInvalidValue, disconnectedTimeoutEnv, envICEDisconnectedTimeoutSec, iceDisconnectedTimeoutDefault)
		return iceDisconnectedTimeoutDefault
	}

	return time.Duration(disconnectedTimeoutSec) * time.Second
}

func iceFailedTimeout() time.Duration {
	failedTimeoutEnv := os.Getenv(envICEFailedTimeoutSec)
	if failedTimeoutEnv == "" {
		return iceFailedTimeoutDefault
	}

	log.Infof("setting ICE failed timeout to %s seconds", failedTimeoutEnv)
	failedTimeoutSec, err := strconv.Atoi(failedTimeoutEnv)
	if err != nil {
		log.Warnf(msgWarnInvalidValue, failedTimeoutEnv, envICEFailedTimeoutSec, iceFailedTimeoutDefault)
		return iceFailedTimeoutDefault
	}

	return time.Duration(failedTimeoutSec) * time.Second
}

func iceRelayAcceptanceMinWait() time.Duration {
	iceRelayAcceptanceMinWaitEnv := os.Getenv(envICERelayAcceptanceMinWaitSec)
	if iceRelayAcceptanceMinWaitEnv == "" {
		return iceRelayAcceptanceMinWaitDefault
	}

	log.Infof("setting ICE relay acceptance min wait to %s seconds", iceRelayAcceptanceMinWaitEnv)
	disconnectedTimeoutSec, err := strconv.Atoi(iceRelayAcceptanceMinWaitEnv)
	if err != nil {
		log.Warnf(msgWarnInvalidValue, iceRelayAcceptanceMinWaitEnv, envICERelayAcceptanceMinWaitSec, iceRelayAcceptanceMinWaitDefault)
		return iceRelayAcceptanceMinWaitDefault
	}

	return time.Duration(disconnectedTimeoutSec) * time.Second
}
