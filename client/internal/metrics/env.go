package metrics

import (
	"net/url"
	"os"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	// EnvMetricsEnabled is the environment variable to enable metrics push (default: disabled)
	EnvMetricsEnabled = "NB_METRICS_ENABLED"

	// EnvMetricsServerURL is the environment variable to override the metrics server URL
	EnvMetricsServerURL = "NB_METRICS_SERVER_URL"

	// EnvMetricsInterval is the environment variable to set the push interval (default: 4h)
	// Format: duration string like "1h", "30m", "4h"
	EnvMetricsInterval = "NB_METRICS_INTERVAL"
)

var (
	defaultMetricsURL *url.URL
)

func init() {
	var err error
	defaultMetricsURL, err = url.Parse("https://api.netbird.io:8428/api/v1/import/prometheus")
	if err != nil {
		log.Fatalf("failed to parse default metrics URL: %v", err)
	}
}

// IsMetricsPushEnabled returns true if metrics push is enabled via NB_METRICS_ENABLED env var
// Disabled by default. Set NB_METRICS_ENABLED=true to enable
func IsMetricsPushEnabled() bool {
	enabled, _ := strconv.ParseBool(os.Getenv(EnvMetricsEnabled))
	return enabled
}

// getMetricsServerURL returns the metrics server URL (never nil)
// First checks NB_METRICS_SERVER_URL environment variable and validates it
// If not set or invalid, returns the default NetBird metrics server (api.netbird.io:8428)
func getMetricsServerURL() url.URL {
	// Check environment variable first
	if envURLStr := os.Getenv(EnvMetricsServerURL); envURLStr != "" {
		envURL, err := url.Parse(envURLStr)
		if err != nil {
			log.Warnf("invalid metrics server URL from env %q: %v, using default", envURLStr, err)
			return *defaultMetricsURL
		}
		return *envURL
	}

	return *defaultMetricsURL
}

// getMetricsInterval returns the metrics push interval from environment variable
// If not set or invalid, returns 0 (which will use the default in NewPush)
func getMetricsInterval() time.Duration {
	if intervalStr := os.Getenv(EnvMetricsInterval); intervalStr != "" {
		interval, err := time.ParseDuration(intervalStr)
		if err != nil {
			log.Warnf("invalid metrics interval from env %q: %v, using default", intervalStr, err)
			return 0
		}
		if interval <= 0 {
			log.Warnf("invalid metrics interval from env %q: must be positive, using default", intervalStr)
			return 0
		}
		return interval
	}
	return 0
}
