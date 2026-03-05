package metrics

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
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

func testConfig(since, until string, period time.Duration) *remoteconfig.Config {
	return &remoteconfig.Config{
		VersionSince: mustVersion(since),
		VersionUntil: mustVersion(until),
		Period:       period,
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

func (m *mockMetrics) RecordConnectionStages(_ context.Context, _ AgentInfo, _ ConnectionType, _ bool, _ ConnectionStageTimestamps) {
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

func TestPush_OverrideIntervalAlwaysPushes(t *testing.T) {
	var pushCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pushCount.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	metrics := &mockMetrics{exportData: "test_metric 1\n"}
	configProvider := &mockConfigProvider{config: nil} // no remote config

	push := &Push{
		metrics:          metrics,
		pushURL:          server.URL,
		agentVersion:     mustVersion("1.0.0"),
		overrideInterval: 50 * time.Millisecond,
		configManager:    configProvider,
		client:           &http.Client{Timeout: 5 * time.Second},
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		push.Start(ctx)
		close(done)
	}()

	// Wait for a few pushes
	require.Eventually(t, func() bool {
		return pushCount.Load() >= 3
	}, 2*time.Second, 10*time.Millisecond)

	cancel()
	<-done
}

func TestPush_RemoteConfigVersionInRange(t *testing.T) {
	var pushCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pushCount.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	metrics := &mockMetrics{exportData: "test_metric 1\n"}
	configProvider := &mockConfigProvider{config: testConfig("1.0.0", "2.0.0", 1*time.Minute)}

	push := &Push{
		metrics:       metrics,
		pushURL:       server.URL,
		agentVersion:  mustVersion("1.5.0"),
		configManager: configProvider,
		client:        &http.Client{Timeout: 5 * time.Second},
	}

	interval, shouldPush := push.resolveInterval(context.Background())
	assert.True(t, shouldPush)
	assert.Equal(t, 1*time.Minute, interval)
	assert.Equal(t, int32(0), pushCount.Load()) // resolveInterval doesn't push
}

func TestPush_RemoteConfigVersionOutOfRange(t *testing.T) {
	metrics := &mockMetrics{exportData: "test_metric 1\n"}
	configProvider := &mockConfigProvider{config: testConfig("1.0.0", "1.5.0", 1*time.Minute)}

	push := &Push{
		metrics:       metrics,
		pushURL:       "http://localhost",
		agentVersion:  mustVersion("2.0.0"),
		configManager: configProvider,
		client:        &http.Client{Timeout: 5 * time.Second},
	}

	interval, shouldPush := push.resolveInterval(context.Background())
	assert.False(t, shouldPush)
	assert.Equal(t, 1*time.Minute, interval)
}

func TestPush_NoConfigReturnsDefault(t *testing.T) {
	metrics := &mockMetrics{}
	configProvider := &mockConfigProvider{config: nil}

	push := &Push{
		metrics:       metrics,
		pushURL:       "http://localhost",
		agentVersion:  mustVersion("1.0.0"),
		configManager: configProvider,
		client:        &http.Client{Timeout: 5 * time.Second},
	}

	interval, shouldPush := push.resolveInterval(context.Background())
	assert.False(t, shouldPush)
	assert.Equal(t, DefaultPushInterval, interval)
}

func TestPush_OverrideIntervalBypassesRemoteConfig(t *testing.T) {
	metrics := &mockMetrics{}
	// Remote config says version is out of range, but override should bypass it
	configProvider := &mockConfigProvider{config: testConfig("3.0.0", "4.0.0", 60*time.Minute)}

	push := &Push{
		metrics:          metrics,
		pushURL:          "http://localhost",
		agentVersion:     mustVersion("1.0.0"),
		overrideInterval: 30 * time.Second,
		configManager:    configProvider,
		client:           &http.Client{Timeout: 5 * time.Second},
	}

	interval, shouldPush := push.resolveInterval(context.Background())
	assert.True(t, shouldPush)
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

	push := &Push{
		metrics: metrics,
		pushURL: server.URL,
		client:  &http.Client{Timeout: 5 * time.Second},
	}

	err := push.push(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, int32(0), pushCount.Load()) // no HTTP request made
}

func TestPush_EmptyURLSkipsStart(t *testing.T) {
	push := &Push{
		pushURL: "",
	}

	// Should return immediately without blocking
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		push.Start(ctx)
		close(done)
	}()

	select {
	case <-done:
		// good, returned immediately
	case <-ctx.Done():
		t.Fatal("Start did not return for empty URL")
	}
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
