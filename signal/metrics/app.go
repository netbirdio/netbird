package metrics

import (
	"go.opentelemetry.io/otel/metric"
)

// AppMetrics holds all the application metrics
type AppMetrics struct {
	metric.Meter

	RegisteredPeers metric.Int64UpDownCounter
	RegisterTimes   metric.Float64Histogram
	RegisterCalls   metric.Int64Counter
	DeregisterCalls metric.Int64Counter
}

func NewAppMetrics(meter metric.Meter) (*AppMetrics, error) {
	registeredPeers, err := meter.Int64UpDownCounter("registered_peers_total")
	if err != nil {
		return nil, err
	}

	registerTimes, err := meter.Float64Histogram("register_times_milliseconds",
		metric.WithExplicitBucketBoundaries(getStandardBucketBoundaries()...))
	if err != nil {
		return nil, err
	}

	registerCalls, err := meter.Int64Counter("register_calls_total")
	if err != nil {
		return nil, err
	}

	deregisterCalls, err := meter.Int64Counter("deregister_calls_total")
	if err != nil {
		return nil, err
	}

	return &AppMetrics{
		Meter:           meter,
		RegisteredPeers: registeredPeers,
		RegisterTimes:   registerTimes,
		RegisterCalls:   registerCalls,
		DeregisterCalls: deregisterCalls,
	}, nil
}

func getStandardBucketBoundaries() []float64 {
	return []float64{
		0.1,
		0.5,
		1,
		5,
		10,
		50,
		100,
		500,
		1000,
		5000,
		10000,
	}
}
