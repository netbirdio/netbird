package metrics

import "go.opentelemetry.io/otel/metric"

type Metrics struct {
	metric.Meter

	Peers             metric.Int64UpDownCounter
	TransferBytesSent metric.Int64Counter
	TransferBytesRecv metric.Int64Counter
}

func NewMetrics(meter metric.Meter) (*Metrics, error) {
	peers, err := meter.Int64UpDownCounter("peers")
	if err != nil {
		return nil, err
	}

	bytesSent, err := meter.Int64Counter("transfer_bytes_sent")
	if err != nil {
		return nil, err
	}

	bytesRecv, err := meter.Int64Counter("transfer_bytes_received")
	if err != nil {
		return nil, err
	}

	return &Metrics{
		Meter:             meter,
		Peers:             peers,
		TransferBytesSent: bytesSent,
		TransferBytesRecv: bytesRecv,
	}, nil
}
