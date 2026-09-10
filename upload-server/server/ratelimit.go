package server

import (
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/http/middleware"
)

const defaultUploadBurst = 100

func newRateLimiter() *middleware.APIRateLimiter {
	cfg, enabled := middleware.RateLimiterConfigFromEnv()
	if os.Getenv(middleware.RateLimitingBurstEnv) == "" {
		cfg.Burst = defaultUploadBurst
	}

	// Rate limiting is enabled by default unless explicitly disabled
	if os.Getenv(middleware.RateLimitingEnabledEnv) == "" {
		enabled = true
	}

	limiter := middleware.NewAPIRateLimiter(cfg)
	limiter.SetEnabled(enabled)

	log.Infof("Upload URL rate limiting: enabled=%t rate=%.0f/min burst=%d trusted_proxies=%q",
		limiter.Enabled(), cfg.RequestsPerMinute, cfg.Burst, os.Getenv(middleware.RateLimitingTrustedProxiesEnv))

	return limiter
}
