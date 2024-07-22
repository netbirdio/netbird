package metrics

import (
	"go.opentelemetry.io/otel/metric"
)

// AppMetrics holds all the application metrics
type AppMetrics struct {
	metric.Meter

	ActivePeers            metric.Int64UpDownCounter
	PeerConnectionDuration metric.Int64Histogram

	Registrations        metric.Int64Counter
	Deregistrations      metric.Int64Counter
	RegistrationFailures metric.Int64Counter
	RegistrationDelay    metric.Float64Histogram
	GetRegistrationDelay metric.Float64Histogram

	MessagesForwarded      metric.Int64Counter
	MessageForwardFailures metric.Int64Counter
	MessageForwardLatency  metric.Float64Histogram
}

func NewAppMetrics(meter metric.Meter) (*AppMetrics, error) {
	activePeers, err := meter.Int64UpDownCounter("active_peers")
	if err != nil {
		return nil, err
	}

	peerConnectionDuration, err := meter.Int64Histogram("peer_connection_duration_seconds",
		metric.WithExplicitBucketBoundaries(getPeerConnectionDurationBucketBoundaries()...))
	if err != nil {
		return nil, err
	}

	registrations, err := meter.Int64Counter("registrations_total")
	if err != nil {
		return nil, err
	}

	deregistrations, err := meter.Int64Counter("deregistrations_total")
	if err != nil {
		return nil, err
	}

	registrationFailures, err := meter.Int64Counter("registration_failures_total")
	if err != nil {
		return nil, err
	}

	registrationDelay, err := meter.Float64Histogram("registration_delay_milliseconds",
		metric.WithExplicitBucketBoundaries(getStandardBucketBoundaries()...))
	if err != nil {
		return nil, err
	}

	getRegistrationDelay, err := meter.Float64Histogram("get_registration_delay_milliseconds",
		metric.WithExplicitBucketBoundaries(getStandardBucketBoundaries()...))
	if err != nil {
		return nil, err
	}

	messagesForwarded, err := meter.Int64Counter("messages_forwarded_total")
	if err != nil {
		return nil, err
	}

	messageForwardFailures, err := meter.Int64Counter("message_forward_failures_total")
	if err != nil {
		return nil, err
	}

	messageForwardLatency, err := meter.Float64Histogram("message_forward_latency_milliseconds",
		metric.WithExplicitBucketBoundaries(getStandardBucketBoundaries()...))
	if err != nil {
		return nil, err
	}

	return &AppMetrics{
		Meter: meter,

		ActivePeers:            activePeers,
		PeerConnectionDuration: peerConnectionDuration,

		Registrations:        registrations,
		Deregistrations:      deregistrations,
		RegistrationFailures: registrationFailures,
		RegistrationDelay:    registrationDelay,
		GetRegistrationDelay: getRegistrationDelay,

		MessagesForwarded:      messagesForwarded,
		MessageForwardFailures: messageForwardFailures,
		MessageForwardLatency:  messageForwardLatency,
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
func getPeerConnectionDurationBucketBoundaries() []float64 {
	return []float64{
		1,
		60,
		// 10m
		600,
		// 1h
		3600,
		// 2h,
		7200,
		// 6h,
		21600,
		// 12h,
		43200,
		// 24h,
		86400,
		// 48h,
		172800,
	}
}
