package remoteconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	goversion "github.com/hashicorp/go-version"
	log "github.com/sirupsen/logrus"
)

const (
	DefaultMinRefreshInterval = 30 * time.Minute
)

// Config holds the parsed remote push configuration
type Config struct {
	ServerURL    url.URL
	VersionSince *goversion.Version
	VersionUntil *goversion.Version
	Interval     time.Duration
}

// rawConfig is the JSON wire format fetched from the remote server
type rawConfig struct {
	ServerURL     string `json:"server_url"`
	VersionSince  string `json:"version-since"`
	VersionUntil  string `json:"version-until"`
	PeriodMinutes int    `json:"period_minutes"`
}

// Manager handles fetching and caching remote push configuration
type Manager struct {
	configURL          string
	minRefreshInterval time.Duration
	client             *http.Client

	mu          sync.Mutex
	lastConfig  *Config
	lastFetched time.Time
}

func NewManager(configURL string, minRefreshInterval time.Duration) *Manager {
	return &Manager{
		configURL:          configURL,
		minRefreshInterval: minRefreshInterval,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// RefreshIfNeeded fetches new config if the cached one is stale.
// Returns the current config (possibly just fetched) or nil if unavailable.
func (m *Manager) RefreshIfNeeded(ctx context.Context) *Config {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.isConfigFresh() {
		return m.lastConfig
	}

	fetchedConfig, err := m.fetch(ctx)
	m.lastFetched = time.Now()
	if err != nil {
		log.Warnf("failed to fetch metrics remote config: %v", err)
		return m.lastConfig // return cached (may be nil)
	}

	m.lastConfig = fetchedConfig

	log.Tracef("fetched metrics remote config: version-since=%s version-until=%s period=%s",
		fetchedConfig.VersionSince, fetchedConfig.VersionUntil, fetchedConfig.Interval)

	return fetchedConfig
}

func (m *Manager) isConfigFresh() bool {
	if m.lastConfig == nil {
		return false
	}
	return time.Since(m.lastFetched) < m.minRefreshInterval
}

func (m *Manager) fetch(ctx context.Context) (*Config, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.configURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}
	defer func() {
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	var raw rawConfig
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if raw.PeriodMinutes <= 0 {
		return nil, fmt.Errorf("invalid period_minutes: %d", raw.PeriodMinutes)
	}

	if raw.ServerURL == "" {
		return nil, fmt.Errorf("server_url is required")
	}

	serverURL, err := url.Parse(raw.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("parse server_url %q: %w", raw.ServerURL, err)
	}

	since, err := goversion.NewVersion(raw.VersionSince)
	if err != nil {
		return nil, fmt.Errorf("parse version-since %q: %w", raw.VersionSince, err)
	}

	until, err := goversion.NewVersion(raw.VersionUntil)
	if err != nil {
		return nil, fmt.Errorf("parse version-until %q: %w", raw.VersionUntil, err)
	}

	return &Config{
		ServerURL:    *serverURL,
		VersionSince: since,
		VersionUntil: until,
		Interval:     time.Duration(raw.PeriodMinutes) * time.Minute,
	}, nil
}
