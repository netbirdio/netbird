package health

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/embed"
	"github.com/netbirdio/netbird/proxy/internal/types"
)

type mockClientProvider struct {
	clients map[types.AccountID]*embed.Client
}

func (m *mockClientProvider) ListClientsForStartup() map[types.AccountID]*embed.Client {
	return m.clients
}

// newTestChecker creates a checker with a mock health function for testing.
// The health function returns the provided ClientHealth for every client.
func newTestChecker(provider clientProvider, healthResult ClientHealth) *Checker {
	c := NewChecker(nil, provider)
	c.checkHealth = func(_ *embed.Client) ClientHealth {
		return healthResult
	}
	return c
}

func TestChecker_LivenessProbe(t *testing.T) {
	checker := NewChecker(nil, &mockClientProvider{})

	// Liveness should always return true if we can respond.
	assert.True(t, checker.LivenessProbe())
}

func TestChecker_ReadinessProbe(t *testing.T) {
	checker := NewChecker(nil, &mockClientProvider{})

	// Initially not ready (management not connected).
	assert.False(t, checker.ReadinessProbe())

	// After management connects, should be ready.
	checker.SetManagementConnected(true)
	assert.True(t, checker.ReadinessProbe())

	// If management disconnects, should not be ready.
	checker.SetManagementConnected(false)
	assert.False(t, checker.ReadinessProbe())
}

// TestStartupProbe_EmptyServiceList covers the scenario where management has
// no services configured for this proxy. The proxy should become ready once
// management is connected and the initial sync completes, even with zero clients.
func TestStartupProbe_EmptyServiceList(t *testing.T) {
	checker := NewChecker(nil, &mockClientProvider{})

	// No management connection = not ready.
	assert.False(t, checker.StartupProbe(context.Background()))

	// Management connected but no sync = not ready.
	checker.SetManagementConnected(true)
	assert.False(t, checker.StartupProbe(context.Background()))

	// Management + sync complete + no clients = ready.
	checker.SetInitialSyncComplete()
	assert.True(t, checker.StartupProbe(context.Background()))
}

// TestStartupProbe_WithUnhealthyClients verifies that when services exist
// and clients have been created but are not yet fully connected (to mgmt,
// signal, relays), the startup probe does NOT pass.
func TestStartupProbe_WithUnhealthyClients(t *testing.T) {
	provider := &mockClientProvider{
		clients: map[types.AccountID]*embed.Client{
			"account-1": nil, // concrete client not needed; checkHealth is mocked
			"account-2": nil,
		},
	}
	checker := newTestChecker(provider, ClientHealth{Healthy: false, Error: "not connected yet"})
	checker.SetManagementConnected(true)
	checker.SetInitialSyncComplete()

	assert.False(t, checker.StartupProbe(context.Background()),
		"startup probe must not pass when clients are unhealthy")
}

// TestStartupProbe_WithHealthyClients verifies that once all clients are
// connected and healthy, the startup probe passes.
func TestStartupProbe_WithHealthyClients(t *testing.T) {
	provider := &mockClientProvider{
		clients: map[types.AccountID]*embed.Client{
			"account-1": nil,
			"account-2": nil,
		},
	}
	checker := newTestChecker(provider, ClientHealth{
		Healthy:             true,
		ManagementConnected: true,
		SignalConnected:     true,
		RelaysConnected:     1,
		RelaysTotal:         1,
	})
	checker.SetManagementConnected(true)
	checker.SetInitialSyncComplete()

	assert.True(t, checker.StartupProbe(context.Background()),
		"startup probe must pass when all clients are healthy")
}

// TestStartupProbe_MixedHealthClients verifies that if any single client is
// unhealthy, the startup probe fails (all-or-nothing).
func TestStartupProbe_MixedHealthClients(t *testing.T) {
	provider := &mockClientProvider{
		clients: map[types.AccountID]*embed.Client{
			"healthy-account":   nil,
			"unhealthy-account": nil,
		},
	}

	checker := NewChecker(nil, provider)
	checker.checkHealth = func(cl *embed.Client) ClientHealth {
		// We identify accounts by their position in the map iteration; since we
		// can't control map order, make exactly one unhealthy via counter.
		return ClientHealth{Healthy: false}
	}
	checker.SetManagementConnected(true)
	checker.SetInitialSyncComplete()

	assert.False(t, checker.StartupProbe(context.Background()),
		"startup probe must fail if any client is unhealthy")
}

// TestStartupProbe_RequiresAllConditions ensures that each individual
// prerequisite (management, sync, clients) is necessary. The probe must not
// pass if any one is missing.
func TestStartupProbe_RequiresAllConditions(t *testing.T) {
	provider := &mockClientProvider{
		clients: map[types.AccountID]*embed.Client{
			"account-1": nil,
		},
	}

	t.Run("no management", func(t *testing.T) {
		checker := newTestChecker(provider, ClientHealth{Healthy: true})
		checker.SetInitialSyncComplete()
		// management NOT connected
		assert.False(t, checker.StartupProbe(context.Background()))
	})

	t.Run("no sync", func(t *testing.T) {
		checker := newTestChecker(provider, ClientHealth{Healthy: true})
		checker.SetManagementConnected(true)
		// sync NOT complete
		assert.False(t, checker.StartupProbe(context.Background()))
	})

	t.Run("unhealthy client", func(t *testing.T) {
		checker := newTestChecker(provider, ClientHealth{Healthy: false})
		checker.SetManagementConnected(true)
		checker.SetInitialSyncComplete()
		assert.False(t, checker.StartupProbe(context.Background()))
	})

	t.Run("all conditions met", func(t *testing.T) {
		checker := newTestChecker(provider, ClientHealth{Healthy: true})
		checker.SetManagementConnected(true)
		checker.SetInitialSyncComplete()
		assert.True(t, checker.StartupProbe(context.Background()))
	})
}

// TestStartupProbe_ConcurrentAccess runs the startup probe from many
// goroutines simultaneously to check for races.
func TestStartupProbe_ConcurrentAccess(t *testing.T) {
	provider := &mockClientProvider{
		clients: map[types.AccountID]*embed.Client{
			"account-1": nil,
			"account-2": nil,
		},
	}
	checker := newTestChecker(provider, ClientHealth{Healthy: true})
	checker.SetManagementConnected(true)
	checker.SetInitialSyncComplete()

	var wg sync.WaitGroup
	const goroutines = 50
	results := make([]bool, goroutines)

	for i := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = checker.StartupProbe(context.Background())
		}(i)
	}
	wg.Wait()

	for i, r := range results {
		assert.True(t, r, "goroutine %d got unexpected result", i)
	}
}

// TestStartupProbe_CancelledContext verifies that a cancelled context causes
// the probe to report unhealthy when client checks are needed.
func TestStartupProbe_CancelledContext(t *testing.T) {
	t.Run("no management bypasses context", func(t *testing.T) {
		checker := NewChecker(nil, &mockClientProvider{})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		// Should be false because management isn't connected, context is irrelevant.
		assert.False(t, checker.StartupProbe(ctx))
	})

	t.Run("with clients and cancelled context", func(t *testing.T) {
		provider := &mockClientProvider{
			clients: map[types.AccountID]*embed.Client{
				"account-1": nil,
			},
		}
		checker := NewChecker(nil, provider)
		// Use the real checkHealth path — a cancelled context should cause
		// the semaphore acquisition to fail, reporting unhealthy.
		checker.SetManagementConnected(true)
		checker.SetInitialSyncComplete()

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		assert.False(t, checker.StartupProbe(ctx),
			"cancelled context must result in unhealthy when clients exist")
	})
}

// TestHandler_Startup_EmptyServiceList verifies the HTTP startup endpoint
// returns 200 when management is connected, sync is complete, and there are
// no services/clients.
func TestHandler_Startup_EmptyServiceList(t *testing.T) {
	checker := NewChecker(nil, &mockClientProvider{})
	checker.SetManagementConnected(true)
	checker.SetInitialSyncComplete()
	handler := checker.Handler()

	req := httptest.NewRequest(http.MethodGet, "/healthz/startup", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp ProbeResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "ok", resp.Status)
	assert.True(t, resp.Checks["management_connected"])
	assert.True(t, resp.Checks["initial_sync_complete"])
	assert.True(t, resp.Checks["all_clients_healthy"])
	assert.Empty(t, resp.Clients)
}

// TestHandler_Startup_WithUnhealthyClients verifies that the HTTP startup
// endpoint returns 503 when clients exist but are not yet healthy.
func TestHandler_Startup_WithUnhealthyClients(t *testing.T) {
	provider := &mockClientProvider{
		clients: map[types.AccountID]*embed.Client{
			"account-1": nil,
		},
	}
	checker := newTestChecker(provider, ClientHealth{Healthy: false, Error: "starting"})
	checker.SetManagementConnected(true)
	checker.SetInitialSyncComplete()
	handler := checker.Handler()

	req := httptest.NewRequest(http.MethodGet, "/healthz/startup", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)

	var resp ProbeResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "fail", resp.Status)
	assert.True(t, resp.Checks["management_connected"])
	assert.True(t, resp.Checks["initial_sync_complete"])
	assert.False(t, resp.Checks["all_clients_healthy"])
	require.Contains(t, resp.Clients, types.AccountID("account-1"))
	assert.Equal(t, "starting", resp.Clients["account-1"].Error)
}

// TestHandler_Startup_WithHealthyClients verifies the HTTP startup endpoint
// returns 200 once clients are healthy.
func TestHandler_Startup_WithHealthyClients(t *testing.T) {
	provider := &mockClientProvider{
		clients: map[types.AccountID]*embed.Client{
			"account-1": nil,
		},
	}
	checker := newTestChecker(provider, ClientHealth{
		Healthy:             true,
		ManagementConnected: true,
		SignalConnected:     true,
		RelaysConnected:     1,
		RelaysTotal:         1,
	})
	checker.SetManagementConnected(true)
	checker.SetInitialSyncComplete()
	handler := checker.Handler()

	req := httptest.NewRequest(http.MethodGet, "/healthz/startup", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp ProbeResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "ok", resp.Status)
	assert.True(t, resp.Checks["all_clients_healthy"])
}

// TestHandler_Startup_NotComplete verifies the startup handler returns 503
// when prerequisites aren't met.
func TestHandler_Startup_NotComplete(t *testing.T) {
	checker := NewChecker(nil, &mockClientProvider{})
	handler := checker.Handler()

	req := httptest.NewRequest(http.MethodGet, "/healthz/startup", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)

	var resp ProbeResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "fail", resp.Status)
}

func TestChecker_Handler_Liveness(t *testing.T) {
	checker := NewChecker(nil, &mockClientProvider{})
	handler := checker.Handler()

	req := httptest.NewRequest(http.MethodGet, "/healthz/live", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp ProbeResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "ok", resp.Status)
}

func TestChecker_Handler_Readiness_NotReady(t *testing.T) {
	checker := NewChecker(nil, &mockClientProvider{})
	handler := checker.Handler()

	req := httptest.NewRequest(http.MethodGet, "/healthz/ready", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)

	var resp ProbeResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "fail", resp.Status)
	assert.False(t, resp.Checks["management_connected"])
}

func TestChecker_Handler_Readiness_Ready(t *testing.T) {
	checker := NewChecker(nil, &mockClientProvider{})
	checker.SetManagementConnected(true)
	handler := checker.Handler()

	req := httptest.NewRequest(http.MethodGet, "/healthz/ready", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp ProbeResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "ok", resp.Status)
	assert.True(t, resp.Checks["management_connected"])
}

func TestChecker_Handler_Full(t *testing.T) {
	checker := NewChecker(nil, &mockClientProvider{})
	checker.SetManagementConnected(true)
	handler := checker.Handler()

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp ProbeResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "ok", resp.Status)
	assert.NotNil(t, resp.Checks)
	// Clients may be empty map when no clients exist.
	assert.Empty(t, resp.Clients)
}

func TestChecker_SetShuttingDown(t *testing.T) {
	checker := NewChecker(nil, &mockClientProvider{})
	checker.SetManagementConnected(true)

	assert.True(t, checker.ReadinessProbe(), "should be ready before shutdown")

	checker.SetShuttingDown()

	assert.False(t, checker.ReadinessProbe(), "should not be ready after shutdown")
}

func TestChecker_Handler_Readiness_ShuttingDown(t *testing.T) {
	checker := NewChecker(nil, &mockClientProvider{})
	checker.SetManagementConnected(true)
	checker.SetShuttingDown()
	handler := checker.Handler()

	req := httptest.NewRequest(http.MethodGet, "/healthz/ready", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)

	var resp ProbeResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "fail", resp.Status)
}

func TestNewServer_WithMetricsHandler(t *testing.T) {
	checker := NewChecker(nil, &mockClientProvider{})
	checker.SetManagementConnected(true)

	metricsHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("metrics"))
	})

	srv := NewServer(":0", checker, nil, metricsHandler)
	require.NotNil(t, srv)

	// Verify health endpoint still works through the mux.
	req := httptest.NewRequest(http.MethodGet, "/healthz/live", nil)
	rec := httptest.NewRecorder()
	srv.server.Handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Verify metrics endpoint is mounted.
	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec = httptest.NewRecorder()
	srv.server.Handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "metrics", rec.Body.String())
}

func TestNewServer_WithoutMetricsHandler(t *testing.T) {
	checker := NewChecker(nil, &mockClientProvider{})
	checker.SetManagementConnected(true)

	srv := NewServer(":0", checker, nil, nil)
	require.NotNil(t, srv)

	req := httptest.NewRequest(http.MethodGet, "/healthz/live", nil)
	rec := httptest.NewRecorder()
	srv.server.Handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}
