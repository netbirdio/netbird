package metrics

import "go.opentelemetry.io/otel/metric"

type Metrics struct {
	metric.Meter

	Peers metric.Int64UpDownCounter
}

func NewMetrics(meter metric.Meter) (*Metrics, error) {
	peers, err := meter.Int64UpDownCounter("peers")
	if err != nil {
		return nil, err
	}

	return &Metrics{
		Meter: meter,
		Peers: peers,
	}, nil
}
