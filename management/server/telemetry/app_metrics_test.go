package telemetry

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sharedMetrics "github.com/netbirdio/netbird/shared/metrics"
)

func TestNewAppMetrics_RegistersWithSharedRegistry(t *testing.T) {
	ctx := context.Background()
	registry, err := sharedMetrics.New(InstrumentationScope())
	require.NoError(t, err)
	t.Cleanup(func() { _ = registry.Shutdown(ctx) })

	appMetrics, err := NewAppMetrics(ctx, registry)
	require.NoError(t, err)
	assert.Same(t, registry, appMetrics.Registry())
	assert.Same(t, registry.Meter, appMetrics.GetMeter())

	appMetrics.StoreMetrics().CountTransactionDuration(3 * time.Millisecond)
	require.NoError(t, registry.Serve(ctx, 0, ""))

	resp, err := http.Get("http://" + registry.Server.Addr + registry.Endpoint)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(body), "management_store_transaction_duration_ms")
	assert.Contains(t, string(body), InstrumentationScope())
}

func TestNewDefaultAppMetrics_OwnsARegistry(t *testing.T) {
	appMetrics, err := NewDefaultAppMetrics(context.Background())
	require.NoError(t, err)
	t.Cleanup(func() { _ = appMetrics.Registry().Shutdown(context.Background()) })

	assert.NotNil(t, appMetrics.Registry())
	assert.NotNil(t, appMetrics.EphemeralPeersMetrics())
}
