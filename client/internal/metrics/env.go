package metrics

import (
	"net/url"
	"os"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	// EnvMetricsPushEnabled controls whether collected metrics are pushed to the backend.
	// Metrics collection itself is always active (for debug bundles).
	// Disabled by default. Set NB_METRICS_PUSH_ENABLED=true to enable push.
	EnvMetricsPushEnabled = "NB_METRICS_PUSH_ENABLED"

	// EnvMetricsForceSending if set to true, skips remote configuration fetch and forces metric sending
	EnvMetricsForceSending = "NB_METRICS_FORCE_SENDING"

	// EnvMetricsConfigURL is the environment variable to override the metrics push config ServerAddress
	EnvMetricsConfigURL = "NB_METRICS_CONFIG_URL"

	// EnvMetricsServerURL is the environment variable to override the metrics server address.
	// When set, this takes precedence over the server_url from remote push config.
	EnvMetricsServerURL = "NB_METRICS_SERVER_URL"

	// EnvMetricsInterval overrides the push interval from the remote config.
	// Only affects how often metrics are pushed; remote config availability
	// and version range checks are still respected.
	// Format: duration string like "1h", "30m", "4h"
	EnvMetricsInterval = "NB_METRICS_INTERVAL"

	defaultMetricsConfigURL = "https://ingest.netbird.io/config"
)

// IsMetricsPushEnabled returns true if metrics push is enabled via NB_METRICS_PUSH_ENABLED env var.
// Disabled by default. Metrics collection is always active for debug bundles.
func IsMetricsPushEnabled() bool {
	enabled, _ := strconv.ParseBool(os.Getenv(EnvMetricsPushEnabled))
	return enabled
}

// getMetricsInterval returns the metrics push interval from NB_METRICS_INTERVAL env var.
// Returns 0 if not set or invalid.
func getMetricsInterval() time.Duration {
	intervalStr := os.Getenv(EnvMetricsInterval)
	if intervalStr == "" {
		return 0
	}
	interval, err := time.ParseDuration(intervalStr)
	if err != nil {
		log.Warnf("invalid metrics interval from env %q: %v", intervalStr, err)
		return 0
	}
	if interval <= 0 {
		log.Warnf("invalid metrics interval from env %q: must be positive", intervalStr)
		return 0
	}
	return interval
}

func isForceSending() bool {
	force, _ := strconv.ParseBool(os.Getenv(EnvMetricsForceSending))
	return force
}

// getMetricsConfigURL returns the URL to fetch push configuration from
func getMetricsConfigURL() string {
	if envURL := os.Getenv(EnvMetricsConfigURL); envURL != "" {
		return envURL
	}
	return defaultMetricsConfigURL
}

// getMetricsServerURL returns the metrics server URL from NB_METRICS_SERVER_URL env var.
// Returns nil if not set or invalid.
func getMetricsServerURL() *url.URL {
	envURL := os.Getenv(EnvMetricsServerURL)
	if envURL == "" {
		return nil
	}
	parsed, err := url.ParseRequestURI(envURL)
	if err != nil || parsed.Host == "" {
		log.Warnf("invalid metrics server URL %q: must be an absolute HTTP(S) URL", envURL)
		return nil
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		log.Warnf("invalid metrics server URL %q: unsupported scheme %q", envURL, parsed.Scheme)
		return nil
	}
	return parsed
}
