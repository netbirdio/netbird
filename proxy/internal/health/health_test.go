package health

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

func TestChecker_StartupProbe_NoClients(t *testing.T) {
	checker := NewChecker(nil, &mockClientProvider{})

	// Initially startup not complete.
	assert.False(t, checker.StartupProbe(context.Background()))

	// Just management connected is not enough.
	checker.SetManagementConnected(true)
	assert.False(t, checker.StartupProbe(context.Background()))

	// Management + initial sync but no clients = not ready
	checker.SetInitialSyncComplete()
	assert.False(t, checker.StartupProbe(context.Background()))
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

func TestChecker_Handler_Startup_NotComplete(t *testing.T) {
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

func TestChecker_StartupProbe_RespectsContext(t *testing.T) {
	checker := NewChecker(nil, &mockClientProvider{})
	checker.SetManagementConnected(true)
	checker.SetInitialSyncComplete()

	// Cancelled context should return false quickly
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := checker.StartupProbe(ctx)
	assert.False(t, result)
}
