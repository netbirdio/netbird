package metrics

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	goversion "github.com/hashicorp/go-version"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/metrics/remoteconfig"
)

const (
	// DefaultPushInterval is the default interval for pushing metrics
	DefaultPushInterval = 5 * time.Minute
)

var (
	DefaultPushConfig = PushConfig{
		URL:      nil,
		Interval: 0,
	}
)

// PushConfig holds configuration for metrics push
type PushConfig struct {
	// URL is the metrics server URL. If nil, uses env var or default
	URL *url.URL
	// Interval is how often to push metrics. If 0, uses env var or default (4h)
	Interval time.Duration
}

// remoteConfigProvider abstracts remote push config fetching for testability
type remoteConfigProvider interface {
	RefreshIfNeeded(ctx context.Context) *remoteconfig.Config
}

// Push handles periodic pushing of metrics to VictoriaMetrics
type Push struct {
	metrics          metricsImplementation
	pushURL          string
	agentVersion     *goversion.Version
	overrideInterval time.Duration // if set, bypass remote config and always push at this interval

	configManager remoteConfigProvider
	client        *http.Client
}

// NewPush creates a new Push instance with configuration resolution
func NewPush(metrics metricsImplementation, configManager remoteConfigProvider, config PushConfig, agentVersion string) *Push {
	// Resolve URL: config > env var (always returns valid URL)
	var pushURL url.URL
	if config.URL != nil {
		pushURL = *config.URL
	} else {
		pushURL = getMetricsServerURL()
	}

	// If interval is explicitly set (config param or env var), bypass remote config entirely
	overrideInterval := config.Interval
	if overrideInterval == 0 {
		overrideInterval = getMetricsInterval() // 0 if env var not set
	}

	parsedVersion, err := goversion.NewVersion(agentVersion)
	if err != nil {
		log.Warnf("failed to parse agent version %q: %v", agentVersion, err)
	}

	return &Push{
		metrics:          metrics,
		pushURL:          pushURL.String(),
		agentVersion:     parsedVersion,
		overrideInterval: overrideInterval,
		configManager:    configManager,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Start starts the periodic push loop.
// If overrideInterval is set (via env var), pushes unconditionally at that interval.
// Otherwise, fetches remote config to determine push period and version eligibility.
func (p *Push) Start(ctx context.Context) {
	if p.pushURL == "" {
		log.Debug("metrics push URL not configured, skipping push")
		return
	}

	timer := time.NewTimer(0) // fire immediately on first iteration
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Debug("stopping metrics push")
			return
		case <-timer.C:
		}

		nextInterval := p.tick(ctx)
		timer.Reset(nextInterval)
	}
}

// tick performs a single push cycle and returns the duration to wait before the next one.
func (p *Push) tick(ctx context.Context) time.Duration {
	interval, shouldPush := p.resolveInterval(ctx)
	if shouldPush {
		if err := p.push(ctx); err != nil {
			log.Errorf("failed to push metrics: %v", err)
		}
	}
	return interval
}

// resolveInterval determines the push interval and whether a push should happen.
// If overrideInterval is set, it bypasses remote config and always pushes.
// Otherwise, it fetches remote config and checks version eligibility.
func (p *Push) resolveInterval(ctx context.Context) (time.Duration, bool) {
	if p.overrideInterval > 0 {
		return p.overrideInterval, true
	}

	config := p.configManager.RefreshIfNeeded(ctx)
	if config == nil {
		log.Debug("no metrics push config available, waiting to retry")
		return DefaultPushInterval, false
	}

	if p.agentVersion == nil {
		log.Debug("agent version not available, skipping metrics push")
		return config.Period, false
	}

	if !isVersionInRange(p.agentVersion, config.VersionSince, config.VersionUntil) {
		log.Debugf("agent version %s not in range [%s, %s), skipping metrics push",
			p.agentVersion, config.VersionSince, config.VersionUntil)
		return config.Period, false
	}

	return config.Period, true
}

// push exports metrics and sends them to VictoriaMetrics
func (p *Push) push(ctx context.Context) error {
	// Export metrics to buffer
	var buf bytes.Buffer
	if err := p.metrics.Export(&buf); err != nil {
		return fmt.Errorf("export metrics: %w", err)
	}

	// Don't push if there are no metrics
	if buf.Len() == 0 {
		log.Tracef("no metrics to push")
		return nil
	}

	// Log what we're pushing (first 500 bytes)
	preview := buf.String()
	if len(preview) > 500 {
		preview = preview[:500]
	}
	log.Tracef("pushing metrics (%d bytes): %s", buf.Len(), preview)

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", p.pushURL, &buf)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "text/plain")

	// Send request
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer func() {
		if resp.Body == nil {
			return
		}
		if err := resp.Body.Close(); err != nil {
			log.Warnf("failed to close response body: %v", err)
		}
	}()

	// Check response status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("push failed with status %d", resp.StatusCode)
	}

	log.Debugf("successfully pushed metrics to %s", p.pushURL)
	p.metrics.Reset()
	return nil
}

// isVersionInRange checks if current falls within [since, until)
func isVersionInRange(current, since, until *goversion.Version) bool {
	return !current.LessThan(since) && current.LessThan(until)
}
