// Package metricstest reads signal metrics collected by an OpenTelemetry manual reader in tests.
package metricstest

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// Collect gathers the current metrics from reader.
func Collect(t *testing.T, reader *sdkmetric.ManualReader) metricdata.ResourceMetrics {
	t.Helper()

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	return rm
}

// SumByAttribute returns the int64 counter or up-down counter name summed per value of the attribute key.
// Data points without the attribute are summed under the empty string.
func SumByAttribute(t *testing.T, rm metricdata.ResourceMetrics, name, key string) map[string]int64 {
	t.Helper()

	m := find(t, rm, name)
	sum, ok := m.Data.(metricdata.Sum[int64])
	require.Truef(t, ok, "%s must be an int64 sum", name)

	counts := make(map[string]int64)
	for _, dp := range sum.DataPoints {
		value, _ := dp.Attributes.Value(attribute.Key(key))
		counts[value.AsString()] += dp.Value
	}
	return counts
}

// HistogramCountByAttribute returns the number of observations recorded by the histogram name per value of the
// attribute key. Data points without the attribute are counted under the empty string.
func HistogramCountByAttribute(t *testing.T, rm metricdata.ResourceMetrics, name, key string) map[string]uint64 {
	t.Helper()

	counts := make(map[string]uint64)
	add := func(set attribute.Set, count uint64) {
		value, _ := set.Value(attribute.Key(key))
		counts[value.AsString()] += count
	}

	switch hist := find(t, rm, name).Data.(type) {
	case metricdata.Histogram[int64]:
		for _, dp := range hist.DataPoints {
			add(dp.Attributes, dp.Count)
		}
	case metricdata.Histogram[float64]:
		for _, dp := range hist.DataPoints {
			add(dp.Attributes, dp.Count)
		}
	default:
		require.Failf(t, "not a histogram", "%s must be a histogram", name)
	}
	return counts
}

func find(t *testing.T, rm metricdata.ResourceMetrics, name string) metricdata.Metrics {
	t.Helper()

	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == name {
				return m
			}
		}
	}
	require.Failf(t, "metric not found", "%s was not recorded", name)
	return metricdata.Metrics{}
}
