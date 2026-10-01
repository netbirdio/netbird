package healthcheck

import (
	"os"
	"strconv"

	log "github.com/sirupsen/logrus"
)

const (
	defaultAttemptThresholdEnv = "NB_RELAY_HC_ATTEMPT_THRESHOLD"
)

func getAttemptThresholdFromEnv() int {
	if attemptThreshold := os.Getenv(defaultAttemptThresholdEnv); attemptThreshold != "" {
		threshold, err := strconv.ParseInt(attemptThreshold, 10, 64)
		if err != nil {
			log.Errorf("Failed to parse attempt threshold from environment variable \"%s\" should be an integer. Using default value", attemptThreshold)
			return defaultAttemptThreshold
		}
		return int(threshold)
	}
	return defaultAttemptThreshold
}
