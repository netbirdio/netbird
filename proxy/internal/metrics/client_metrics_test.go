package metrics_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/netbirdio/netbird/proxy/internal/metrics"
)

func TestRegisterClientObserver(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	m, err := metrics.New(context.Background(), provider.Meter("test"))
	require.NoError(t, err)

	clients := 2
	require.NoError(t, m.RegisterClientObserver(func() int { return clients }))

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	assert.Equal(t, int64(2), gaugeValue(t, rm, "proxy.clients.count"), "gauge must report the current client count")

	clients = 1
	require.NoError(t, reader.Collect(context.Background(), &rm))
	assert.Equal(t, int64(1), gaugeValue(t, rm, "proxy.clients.count"), "gauge must follow the client count on the next collection")
}

func gaugeValue(t *testing.T, rm metricdata.ResourceMetrics, name string) int64 {
	t.Helper()

	for _, sm := range rm.ScopeMetrics {
		for _, mtr := range sm.Metrics {
			if mtr.Name != name {
				continue
			}
			gauge, ok := mtr.Data.(metricdata.Gauge[int64])
			require.True(t, ok, "%s must be an int64 gauge", name)
			require.Len(t, gauge.DataPoints, 1, "%s must have a single data point", name)
			return gauge.DataPoints[0].Value
		}
	}
	t.Fatalf("gauge %s not found", name)
	return 0
}
