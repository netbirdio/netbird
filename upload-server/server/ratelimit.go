package server

import (
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/http/middleware"
)

const defaultUploadBurst = 100

func newRateLimiter() *middleware.APIRateLimiter {
	cfg, _ := middleware.RateLimiterConfigFromEnv()
	if os.Getenv(middleware.RateLimitingBurstEnv) == "" {
		cfg.Burst = defaultUploadBurst
	}

	limiter := middleware.NewAPIRateLimiter(cfg)
	if os.Getenv(middleware.RateLimitingEnabledEnv) == "false" {
		limiter.SetEnabled(false)
	}

	log.Infof("Upload URL rate limiting: enabled=%t rate=%.0f/min burst=%d trusted_proxies=%q",
		limiter.Enabled(), cfg.RequestsPerMinute, cfg.Burst, os.Getenv(middleware.RateLimitingTrustedProxiesEnv))

	return limiter
}
