package metrics

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	// DefaultPushInterval is the default interval for pushing metrics
	DefaultPushInterval = 5 * time.Minute
)

var (
	DefaultPushConfig = PushConfig{
		URL:      nil, // Will use getMetricsServerURL()
		Interval: 0,   // Will use getMetricsInterval() or DefaultPushInterval
	}
)

// PushConfig holds configuration for metrics push
type PushConfig struct {
	// URL is the metrics server URL. If nil, uses env var or default
	URL *url.URL
	// Interval is how often to push metrics. If 0, uses env var or default (4h)
	Interval time.Duration
}

// Push handles periodic pushing of metrics to VictoriaMetrics
type Push struct {
	metrics  metricsImplementation
	pushURL  string
	interval time.Duration
	client   *http.Client
}

// NewPush creates a new Push instance with configuration resolution
// Precedence: config parameter > env var > DefaultPushConfig
func NewPush(metrics metricsImplementation, config PushConfig) *Push {
	// Resolve URL: config > env var (always returns valid URL)
	var pushURL url.URL
	if config.URL != nil {
		pushURL = *config.URL
	} else {
		pushURL = getMetricsServerURL()
	}

	// Resolve interval: config > env var > default
	interval := config.Interval
	if interval == 0 {
		if envInterval := getMetricsInterval(); envInterval > 0 {
			interval = envInterval
		} else {
			interval = DefaultPushInterval
		}
	}

	return &Push{
		metrics:  metrics,
		pushURL:  pushURL.String(),
		interval: interval,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Start starts the periodic push ticker
// Pushes immediately on start, then every interval
func (p *Push) Start(ctx context.Context) {
	if p.pushURL == "" {
		log.Debug("metrics push URL not configured, skipping push")
		return
	}

	// Push immediately on start
	if err := p.push(ctx); err != nil {
		log.Errorf("failed to push metrics on start: %v", err)
	}

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Debug("stopping metrics push")
			return
		case <-ticker.C:
			if err := p.push(ctx); err != nil {
				log.Errorf("failed to push metrics: %v", err)
			}
		}
	}
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
	return nil
}
