package remoteconfig

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testMinRefresh = 100 * time.Millisecond

func TestManager_FetchSuccess(t *testing.T) {
	server := newConfigServer(t, rawConfig{
		ServerURL:     "https://ingest.example.com",
		VersionSince:  "1.0.0",
		VersionUntil:  "2.0.0",
		PeriodMinutes: 60,
	})
	defer server.Close()

	mgr := NewManager(server.URL, testMinRefresh)
	config := mgr.RefreshIfNeeded(context.Background())

	require.NotNil(t, config)
	assert.Equal(t, "https://ingest.example.com", config.ServerURL.String())
	assert.Equal(t, "1.0.0", config.VersionSince.String())
	assert.Equal(t, "2.0.0", config.VersionUntil.String())
	assert.Equal(t, 60*time.Minute, config.Interval)
}

func TestManager_CachesConfig(t *testing.T) {
	var fetchCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount.Add(1)
		err := json.NewEncoder(w).Encode(rawConfig{
			ServerURL:     "https://ingest.example.com",
			VersionSince:  "1.0.0",
			VersionUntil:  "2.0.0",
			PeriodMinutes: 60,
		})
		require.NoError(t, err)
	}))
	defer server.Close()

	mgr := NewManager(server.URL, testMinRefresh)

	// First call fetches
	config1 := mgr.RefreshIfNeeded(context.Background())
	require.NotNil(t, config1)
	assert.Equal(t, int32(1), fetchCount.Load())

	// Second call uses cache (within minRefreshInterval)
	config2 := mgr.RefreshIfNeeded(context.Background())
	require.NotNil(t, config2)
	assert.Equal(t, int32(1), fetchCount.Load())
	assert.Equal(t, config1, config2)
}

func TestManager_RefetchesWhenStale(t *testing.T) {
	var fetchCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount.Add(1)
		err := json.NewEncoder(w).Encode(rawConfig{
			ServerURL:     "https://ingest.example.com",
			VersionSince:  "1.0.0",
			VersionUntil:  "2.0.0",
			PeriodMinutes: 60,
		})
		require.NoError(t, err)
	}))
	defer server.Close()

	mgr := NewManager(server.URL, testMinRefresh)

	// First fetch
	mgr.RefreshIfNeeded(context.Background())
	assert.Equal(t, int32(1), fetchCount.Load())

	// Wait for config to become stale
	time.Sleep(testMinRefresh + 10*time.Millisecond)

	// Should refetch
	mgr.RefreshIfNeeded(context.Background())
	assert.Equal(t, int32(2), fetchCount.Load())
}

func TestManager_FetchFailureReturnsNil(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	mgr := NewManager(server.URL, testMinRefresh)
	config := mgr.RefreshIfNeeded(context.Background())

	assert.Nil(t, config)
}

func TestManager_FetchFailureReturnsCached(t *testing.T) {
	var fetchCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount.Add(1)
		if fetchCount.Load() > 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		err := json.NewEncoder(w).Encode(rawConfig{
			ServerURL:     "https://ingest.example.com",
			VersionSince:  "1.0.0",
			VersionUntil:  "2.0.0",
			PeriodMinutes: 60,
		})
		require.NoError(t, err)
	}))
	defer server.Close()

	mgr := NewManager(server.URL, testMinRefresh)

	// First call succeeds
	config1 := mgr.RefreshIfNeeded(context.Background())
	require.NotNil(t, config1)

	// Wait for config to become stale
	time.Sleep(testMinRefresh + 10*time.Millisecond)

	// Second call fails but returns cached
	config2 := mgr.RefreshIfNeeded(context.Background())
	require.NotNil(t, config2)
	assert.Equal(t, config1, config2)
}

func TestManager_RejectsInvalidPeriod(t *testing.T) {
	tests := []struct {
		name   string
		period int
	}{
		{"zero", 0},
		{"negative", -5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newConfigServer(t, rawConfig{
				ServerURL:     "https://ingest.example.com",
				VersionSince:  "1.0.0",
				VersionUntil:  "2.0.0",
				PeriodMinutes: tt.period,
			})
			defer server.Close()

			mgr := NewManager(server.URL, testMinRefresh)
			config := mgr.RefreshIfNeeded(context.Background())
			assert.Nil(t, config)
		})
	}
}

func TestManager_RejectsEmptyServerURL(t *testing.T) {
	server := newConfigServer(t, rawConfig{
		ServerURL:     "",
		VersionSince:  "1.0.0",
		VersionUntil:  "2.0.0",
		PeriodMinutes: 60,
	})
	defer server.Close()

	mgr := NewManager(server.URL, testMinRefresh)
	config := mgr.RefreshIfNeeded(context.Background())
	assert.Nil(t, config)
}

func TestManager_RejectsInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte("not json"))
		require.NoError(t, err)
	}))
	defer server.Close()

	mgr := NewManager(server.URL, testMinRefresh)
	config := mgr.RefreshIfNeeded(context.Background())
	assert.Nil(t, config)
}

func newConfigServer(t *testing.T, config rawConfig) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(config)
		require.NoError(t, err)
	}))
}
