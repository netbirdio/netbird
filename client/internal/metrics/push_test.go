package metrics

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	goversion "github.com/hashicorp/go-version"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/metrics/remoteconfig"
)

func mustVersion(s string) *goversion.Version {
	v, err := goversion.NewVersion(s)
	if err != nil {
		panic(err)
	}
	return v
}

func mustURL(s string) url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return *u
}

func parseURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

func testConfig(serverURL, since, until string, period time.Duration) *remoteconfig.Config {
	return &remoteconfig.Config{
		ServerURL:    mustURL(serverURL),
		VersionSince: mustVersion(since),
		VersionUntil: mustVersion(until),
		Interval:     period,
	}
}

// mockConfigProvider implements remoteConfigProvider for testing
type mockConfigProvider struct {
	config *remoteconfig.Config
}

func (m *mockConfigProvider) RefreshIfNeeded(_ context.Context) *remoteconfig.Config {
	return m.config
}

// mockMetrics implements metricsImplementation for testing
type mockMetrics struct {
	exportData string
}

func (m *mockMetrics) RecordConnectionStages(_ context.Context, _ AgentInfo, _ string, _ ConnectionType, _ bool, _ ConnectionStageTimestamps) {
}

func (m *mockMetrics) RecordSyncDuration(_ context.Context, _ AgentInfo, _ time.Duration) {
}

func (m *mockMetrics) Export(w io.Writer) error {
	if m.exportData != "" {
		_, err := w.Write([]byte(m.exportData))
		return err
	}
	return nil
}

func (m *mockMetrics) ExportAndReset(w io.Writer) error {
	return m.Export(w)
}

func TestPush_OverrideIntervalPushes(t *testing.T) {
	var pushCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pushCount.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	metrics := &mockMetrics{exportData: "test_metric 1\n"}
	configProvider := &mockConfigProvider{config: testConfig(server.URL, "1.0.0", "2.0.0", 60*time.Minute)}

	push, err := NewPush(metrics, configProvider, PushConfig{
		Interval:      50 * time.Millisecond,
		ServerAddress: parseURL(server.URL),
	}, "1.0.0")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		push.Start(ctx)
		close(done)
	}()

	require.Eventually(t, func() bool {
		return pushCount.Load() >= 3
	}, 2*time.Second, 10*time.Millisecond)

	cancel()
	<-done
}

func TestPush_RemoteConfigVersionInRange(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	metrics := &mockMetrics{exportData: "test_metric 1\n"}
	configProvider := &mockConfigProvider{config: testConfig(server.URL, "1.0.0", "2.0.0", 1*time.Minute)}

	push, err := NewPush(metrics, configProvider, PushConfig{}, "1.5.0")
	require.NoError(t, err)

	pushURL, interval := push.resolve(context.Background())
	assert.NotEmpty(t, pushURL)
	assert.Equal(t, 1*time.Minute, interval)
}

func TestPush_RemoteConfigVersionOutOfRange(t *testing.T) {
	metrics := &mockMetrics{exportData: "test_metric 1\n"}
	configProvider := &mockConfigProvider{config: testConfig("http://localhost", "1.0.0", "1.5.0", 1*time.Minute)}

	push, err := NewPush(metrics, configProvider, PushConfig{}, "2.0.0")
	require.NoError(t, err)

	pushURL, interval := push.resolve(context.Background())
	assert.Empty(t, pushURL)
	assert.Equal(t, 1*time.Minute, interval)
}

func TestPush_NoConfigReturnsDefault(t *testing.T) {
	metrics := &mockMetrics{}
	configProvider := &mockConfigProvider{config: nil}

	push, err := NewPush(metrics, configProvider, PushConfig{}, "1.0.0")
	require.NoError(t, err)

	pushURL, interval := push.resolve(context.Background())
	assert.Empty(t, pushURL)
	assert.Equal(t, defaultPushInterval, interval)
}

func TestPush_OverrideIntervalRespectsVersionCheck(t *testing.T) {
	metrics := &mockMetrics{}
	configProvider := &mockConfigProvider{config: testConfig("http://localhost", "3.0.0", "4.0.0", 60*time.Minute)}

	push, err := NewPush(metrics, configProvider, PushConfig{
		Interval:      30 * time.Second,
		ServerAddress: parseURL("http://localhost"),
	}, "1.0.0")
	require.NoError(t, err)

	pushURL, interval := push.resolve(context.Background())
	assert.Empty(t, pushURL)                  // version out of range
	assert.Equal(t, 30*time.Second, interval) // but uses override interval
}

func TestPush_OverrideIntervalUsedWhenVersionInRange(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	metrics := &mockMetrics{}
	configProvider := &mockConfigProvider{config: testConfig(server.URL, "1.0.0", "2.0.0", 60*time.Minute)}

	push, err := NewPush(metrics, configProvider, PushConfig{
		Interval: 30 * time.Second,
	}, "1.5.0")
	require.NoError(t, err)

	pushURL, interval := push.resolve(context.Background())
	assert.NotEmpty(t, pushURL)
	assert.Equal(t, 30*time.Second, interval)
}

func TestPush_NoMetricsSkipsPush(t *testing.T) {
	var pushCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pushCount.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	metrics := &mockMetrics{exportData: ""} // no metrics to export
	configProvider := &mockConfigProvider{config: nil}

	push, err := NewPush(metrics, configProvider, PushConfig{}, "1.0.0")
	require.NoError(t, err)

	err = push.push(context.Background(), server.URL)
	assert.NoError(t, err)
	assert.Equal(t, int32(0), pushCount.Load())
}

func TestPush_ServerURLFromRemoteConfig(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	metrics := &mockMetrics{exportData: "test_metric 1\n"}
	configProvider := &mockConfigProvider{config: testConfig(server.URL, "1.0.0", "2.0.0", 1*time.Minute)}

	push, err := NewPush(metrics, configProvider, PushConfig{}, "1.5.0")
	require.NoError(t, err)

	pushURL, interval := push.resolve(context.Background())
	assert.Contains(t, pushURL, server.URL)
	assert.Equal(t, 1*time.Minute, interval)
}

func TestPush_ServerAddressOverridesTakePrecedenceOverRemoteConfig(t *testing.T) {
	overrideServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer overrideServer.Close()

	metrics := &mockMetrics{exportData: "test_metric 1\n"}
	configProvider := &mockConfigProvider{config: testConfig("http://remote-config-server", "1.0.0", "2.0.0", 1*time.Minute)}

	push, err := NewPush(metrics, configProvider, PushConfig{
		ServerAddress: parseURL(overrideServer.URL),
	}, "1.5.0")
	require.NoError(t, err)

	pushURL, _ := push.resolve(context.Background())
	assert.Contains(t, pushURL, overrideServer.URL)
	assert.NotContains(t, pushURL, "remote-config-server")
}

func TestPush_OverrideIntervalWithoutOverrideURL_UsesRemoteConfigURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	metrics := &mockMetrics{exportData: "test_metric 1\n"}
	configProvider := &mockConfigProvider{config: testConfig(server.URL, "1.0.0", "2.0.0", 60*time.Minute)}

	push, err := NewPush(metrics, configProvider, PushConfig{
		Interval: 30 * time.Second,
	}, "1.0.0")
	require.NoError(t, err)

	pushURL, interval := push.resolve(context.Background())
	assert.Contains(t, pushURL, server.URL)
	assert.Equal(t, 30*time.Second, interval)
}

func TestPush_NoConfigSkipsPush(t *testing.T) {
	metrics := &mockMetrics{exportData: "test_metric 1\n"}
	configProvider := &mockConfigProvider{config: nil}

	push, err := NewPush(metrics, configProvider, PushConfig{
		Interval: 30 * time.Second,
	}, "1.0.0")
	require.NoError(t, err)

	pushURL, interval := push.resolve(context.Background())
	assert.Empty(t, pushURL)
	assert.Equal(t, defaultPushInterval, interval) // no config available, use default retry interval
}

func TestPush_ForceSendingSkipsRemoteConfig(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	metrics := &mockMetrics{exportData: "test_metric 1\n"}
	configProvider := &mockConfigProvider{config: nil}

	push, err := NewPush(metrics, configProvider, PushConfig{
		ForceSending:  true,
		Interval:      1 * time.Minute,
		ServerAddress: parseURL(server.URL),
	}, "1.0.0")
	require.NoError(t, err)

	pushURL, interval := push.resolve(context.Background())
	assert.NotEmpty(t, pushURL)
	assert.Equal(t, 1*time.Minute, interval)
}

func TestPush_ForceSendingUsesDefaultInterval(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	metrics := &mockMetrics{exportData: "test_metric 1\n"}
	configProvider := &mockConfigProvider{config: nil}

	push, err := NewPush(metrics, configProvider, PushConfig{
		ForceSending:  true,
		ServerAddress: parseURL(server.URL),
	}, "1.0.0")
	require.NoError(t, err)

	pushURL, interval := push.resolve(context.Background())
	assert.NotEmpty(t, pushURL)
	assert.Equal(t, defaultPushInterval, interval)
}

func TestIsVersionInRange(t *testing.T) {
	tests := []struct {
		name     string
		current  string
		since    string
		until    string
		expected bool
	}{
		{"at lower bound inclusive", "1.2.2", "1.2.2", "1.2.3", true},
		{"in range", "1.2.2", "1.2.0", "1.3.0", true},
		{"at upper bound exclusive", "1.2.3", "1.2.2", "1.2.3", false},
		{"below range", "1.2.1", "1.2.2", "1.2.3", false},
		{"above range", "1.3.0", "1.2.2", "1.2.3", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isVersionInRange(mustVersion(tt.current), mustVersion(tt.since), mustVersion(tt.until)))
		})
	}
}
