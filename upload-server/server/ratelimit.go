package server

import (
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/shared/ratelimit"
)

const defaultUploadBurst = 100

func newRateLimiter() *ratelimit.APIRateLimiter {
	cfg, enabled := ratelimit.RateLimiterConfigFromEnv()
	if os.Getenv(ratelimit.RateLimitingBurstEnv) == "" {
		cfg.Burst = defaultUploadBurst
	}

	// Rate limiting is enabled by default unless explicitly disabled
	if os.Getenv(ratelimit.RateLimitingEnabledEnv) == "" {
		enabled = true
	}

	limiter := ratelimit.NewAPIRateLimiter(cfg)
	limiter.SetEnabled(enabled)

	log.Infof("Upload URL rate limiting: enabled=%t rate=%.0f/min burst=%d trusted_proxies=%q",
		limiter.Enabled(), cfg.RequestsPerMinute, cfg.Burst, os.Getenv(ratelimit.RateLimitingTrustedProxiesEnv))

	return limiter
}
