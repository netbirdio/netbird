package proxy

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// New maps Config onto Server field by field, and a field left out of that
// literal still compiles: the knob is simply parsed and then dropped, so an
// operator setting it sees the default with no error anywhere. These assertions
// are the only thing standing between a new setting and that silent no-op.
func TestNew_ForwardsOperatorTuning(t *testing.T) {
	cfg := Config{
		ManagementAddress:            "http://localhost:8080",
		ProxyToken:                   "token",
		CrowdSecAPIURL:               "http://crowdsec:8080/",
		CrowdSecAPIKey:               "key",
		CrowdSecAppSecURL:            "http://crowdsec:7422/",
		CrowdSecAppSecTimeout:        321 * time.Millisecond,
		CrowdSecAppSecMaxBodyBytes:   4321,
		CrowdSecAppSecMaxConcurrent:  17,
		MiddlewareCaptureBudgetBytes: 5 << 20,
		MaxDialTimeout:               7 * time.Second,
		MaxSessionIdleTimeout:        11 * time.Second,
		GeoDataDir:                   "/var/lib/geo",
	}

	srv := New(context.Background(), cfg)
	require.NotNil(t, srv)

	assert.Equal(t, cfg.CrowdSecAPIURL, srv.CrowdSecAPIURL)
	assert.Equal(t, cfg.CrowdSecAPIKey, srv.CrowdSecAPIKey)
	assert.Equal(t, cfg.CrowdSecAppSecURL, srv.CrowdSecAppSecURL)
	assert.Equal(t, cfg.CrowdSecAppSecTimeout, srv.CrowdSecAppSecTimeout)
	assert.Equal(t, cfg.CrowdSecAppSecMaxBodyBytes, srv.CrowdSecAppSecMaxBodyBytes)
	assert.Equal(t, cfg.CrowdSecAppSecMaxConcurrent, srv.CrowdSecAppSecMaxConcurrent)
	assert.Equal(t, cfg.MiddlewareCaptureBudgetBytes, srv.MiddlewareCaptureBudgetBytes)
	assert.Equal(t, cfg.MaxDialTimeout, srv.MaxDialTimeout)
	assert.Equal(t, cfg.MaxSessionIdleTimeout, srv.MaxSessionIdleTimeout)
	assert.Equal(t, cfg.GeoDataDir, srv.GeoDataDir)
}
