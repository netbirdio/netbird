// Package hbmetricstest reads aligned heartbeat counters in tests.
package hbmetricstest

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// NewMeter returns a meter and the reader that collects what it records.
func NewMeter() (metric.Meter, *sdkmetric.ManualReader) {
	reader := sdkmetric.NewManualReader()
	return sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("test"), reader
}

// Counts returns every int64 counter of reader by name. A data point with a
// reason attribute is keyed by name, slash, reason.
func Counts(t *testing.T, reader *sdkmetric.ManualReader) map[string]int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	out := map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				continue
			}
			for _, dp := range sum.DataPoints {
				key := m.Name
				if v, ok := dp.Attributes.Value("reason"); ok {
					key += "/" + v.AsString()
				}
				out[key] += dp.Value
			}
		}
	}
	return out
}
