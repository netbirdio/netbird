package metrics

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	goversion "github.com/hashicorp/go-version"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/metrics/remoteconfig"
)

const (
	// defaultPushInterval is the default interval for pushing metrics
	defaultPushInterval = 5 * time.Minute
)

// defaultMetricsServerURL is used as fallback when NB_METRICS_FORCE_SENDING is true
var defaultMetricsServerURL *url.URL

func init() {
	defaultMetricsServerURL, _ = url.Parse("https://ingest.stage.npeer.io")
}

// PushConfig holds configuration for metrics push
type PushConfig struct {
	// ServerAddress is the metrics server URL. If nil, uses remote config server_url.
	ServerAddress *url.URL
	// Interval is how often to push metrics. If 0, uses remote config interval or defaultPushInterval.
	Interval time.Duration
	// ForceSending skips remote configuration fetch and version checks, pushing unconditionally.
	ForceSending bool
}

// PushConfigFromEnv builds a PushConfig from environment variables.
func PushConfigFromEnv() PushConfig {
	config := PushConfig{}

	config.ForceSending = isForceSending()
	config.ServerAddress = getMetricsServerURL()
	config.Interval = getMetricsInterval()

	return config
}

// remoteConfigProvider abstracts remote push config fetching for testability
type remoteConfigProvider interface {
	RefreshIfNeeded(ctx context.Context) *remoteconfig.Config
}

// Push handles periodic pushing of metrics
type Push struct {
	metrics       metricsImplementation
	configManager remoteConfigProvider
	config        PushConfig
	agentVersion  *goversion.Version

	peerID string
	peerMu sync.RWMutex

	client      *http.Client
	envInterval time.Duration
	envAddress  *url.URL
}

// NewPush creates a new Push instance with configuration resolution
func NewPush(metrics metricsImplementation, configManager remoteConfigProvider, config PushConfig, agentVersion string) (*Push, error) {
	var envInterval time.Duration
	var envAddress *url.URL

	if config.ForceSending {
		envInterval = config.Interval
		if config.Interval <= 0 {
			envInterval = defaultPushInterval
		}

		envAddress = config.ServerAddress
		if envAddress == nil {
			envAddress = defaultMetricsServerURL
		}
	} else {
		envAddress = config.ServerAddress

		if config.Interval < 0 {
			log.Warnf("negative metrics push interval %s", config.Interval)
		} else {
			envInterval = config.Interval
		}
	}

	parsedVersion, err := goversion.NewVersion(agentVersion)
	if err != nil {
		if !config.ForceSending {
			return nil, fmt.Errorf("failed to parse agent version %q: %w", agentVersion, err)
		}
	}

	return &Push{
		metrics:       metrics,
		configManager: configManager,
		config:        config,
		agentVersion:  parsedVersion,
		envInterval:   envInterval,
		envAddress:    envAddress,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}, nil
}

// SetPeerID updates the hashed peer ID used for the Authorization header.
func (p *Push) SetPeerID(peerID string) {
	p.peerMu.Lock()
	p.peerID = peerID
	p.peerMu.Unlock()
}

// Start starts the periodic push loop.
// If overrideInterval is set (via env var), pushes unconditionally at that interval.
// Otherwise, fetches remote config to determine push period and version eligibility.
func (p *Push) Start(ctx context.Context) {
	// Log initial state
	switch {
	case p.config.ForceSending:
		log.Infof("started metrics push with force sending to %s, interval %s", p.envAddress, p.envInterval)
	case p.config.ServerAddress != nil:
		log.Infof("started metrics push with server URL override: %s", p.config.ServerAddress.String())
	default:
		log.Infof("started metrics push, server URL will be resolved from remote config")
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

		pushURL, interval := p.resolve(ctx)
		if pushURL != "" {
			if err := p.push(ctx, pushURL); err != nil {
				log.Errorf("failed to push metrics: %v", err)
			}
		}

		timer.Reset(interval)
	}
}

// resolve returns the push URL and interval for the next cycle.
// Returns empty pushURL to skip this cycle.
func (p *Push) resolve(ctx context.Context) (pushURL string, interval time.Duration) {
	if p.config.ForceSending {
		return p.resolveServerURL(nil), p.envInterval
	}

	config := p.configManager.RefreshIfNeeded(ctx)
	if config == nil {
		log.Debug("no metrics push config available, waiting to retry")
		return "", defaultPushInterval
	}

	interval = config.Interval
	if p.envInterval > 0 {
		interval = p.envInterval
	}

	if !isVersionInRange(p.agentVersion, config.VersionSince, config.VersionUntil) {
		log.Debugf("agent version %s not in range [%s, %s), skipping metrics push",
			p.agentVersion, config.VersionSince, config.VersionUntil)
		return "", interval
	}

	pushURL = p.resolveServerURL(&config.ServerURL)
	if pushURL == "" {
		log.Warn("no metrics server URL available, skipping push")
	}
	return pushURL, interval
}

// push exports metrics and sends them to the metrics server
func (p *Push) push(ctx context.Context, pushURL string) error {
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

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", pushURL, &buf)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")

	p.peerMu.RLock()
	peerID := p.peerID
	p.peerMu.RUnlock()
	if peerID != "" {
		req.Header.Set("Authorization", peerID)
	}

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

	log.Debugf("successfully pushed metrics to %s", pushURL)
	p.metrics.Reset()
	return nil
}

// resolveServerURL determines the push URL.
// Precedence: envAddress (env var) > remote config server_url
func (p *Push) resolveServerURL(remoteServerURL *url.URL) string {
	var baseURL *url.URL
	if p.envAddress != nil {
		baseURL = p.envAddress
	} else {
		baseURL = remoteServerURL
	}

	if baseURL == nil {
		return ""
	}

	return baseURL.String()
}

// isVersionInRange checks if current falls within [since, until)
func isVersionInRange(current, since, until *goversion.Version) bool {
	return !current.LessThan(since) && current.LessThan(until)
}
