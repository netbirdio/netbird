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

	MessagesReceived metric.Int64Counter
	MessageSize      metric.Int64Histogram
	ProbeMessages    metric.Int64Counter
	SendSuccess      metric.Int64Counter
	SendFailures     metric.Int64Counter
	SendInflight     metric.Int64UpDownCounter
}

func NewAppMetrics(meter metric.Meter, prefix ...string) (*AppMetrics, error) {
	p := ""
	if len(prefix) > 0 {
		p = prefix[0]
	}
	activePeers, err := meter.Int64UpDownCounter(p+"active_peers",
		metric.WithDescription("Number of active connected peers"),
	)
	if err != nil {
		return nil, err
	}

	peerConnectionDuration, err := meter.Int64Histogram(p+"peer_connection_duration_seconds",
		metric.WithExplicitBucketBoundaries(getPeerConnectionDurationBucketBoundaries()...),
		metric.WithDescription("Duration of how long a peer was connected"),
	)
	if err != nil {
		return nil, err
	}

	registrations, err := meter.Int64Counter(p+"registrations_total",
		metric.WithDescription("Total number of peer registrations, including streams that replace an existing registration"),
	)
	if err != nil {
		return nil, err
	}

	deregistrations, err := meter.Int64Counter(p+"deregistrations_total",
		metric.WithDescription("Total number of peer deregistrations"),
	)
	if err != nil {
		return nil, err
	}

	registrationFailures, err := meter.Int64Counter(p+"registration_failures_total",
		metric.WithDescription("Total number of peer registration failures"),
	)
	if err != nil {
		return nil, err
	}

	registrationDelay, err := meter.Float64Histogram(p+"registration_delay_milliseconds",
		metric.WithExplicitBucketBoundaries(getStandardBucketBoundaries()...),
		metric.WithDescription("Duration of a peer registration including the dispatcher subscription"),
	)
	if err != nil {
		return nil, err
	}

	getRegistrationDelay, err := meter.Float64Histogram(p+"get_registration_delay_milliseconds",
		metric.WithExplicitBucketBoundaries(getStandardBucketBoundaries()...),
		metric.WithDescription("Duration of how long it takes to load a connection from the registry"),
	)
	if err != nil {
		return nil, err
	}

	messagesForwarded, err := meter.Int64Counter(p+"messages_forwarded_total",
		metric.WithDescription("Total number of messages delivered to a peer stream on this node"),
	)
	if err != nil {
		return nil, err
	}

	messageForwardFailures, err := meter.Int64Counter(p+"message_forward_failures_total",
		metric.WithDescription("Total number of failed deliveries to a peer stream on this node"),
	)
	if err != nil {
		return nil, err
	}

	messageForwardLatency, err := meter.Float64Histogram(p+"message_forward_latency_milliseconds",
		metric.WithExplicitBucketBoundaries(getStandardBucketBoundaries()...),
		metric.WithDescription("Duration of a delivery attempt to a peer stream on this node, labelled by result"),
	)
	if err != nil {
		return nil, err
	}

	messagesReceived, err := meter.Int64Counter(p+"messages_received_total",
		metric.WithDescription("Total number of messages received through Send, counted before routing"),
	)
	if err != nil {
		return nil, err
	}

	messageSize, err := meter.Int64Histogram(
		p+"message.size.bytes",
		metric.WithUnit("bytes"),
		metric.WithExplicitBucketBoundaries(getMessageSizeBucketBoundaries()...),
		metric.WithDescription("Records the size of each message received through Send"),
	)
	if err != nil {
		return nil, err
	}

	probeMessages, err := meter.Int64Counter(p+"probe_messages_total",
		metric.WithDescription("Total number of self-addressed probe messages received through Send"),
	)
	if err != nil {
		return nil, err
	}

	sendSuccess, err := meter.Int64Counter(p+"send_success_total",
		metric.WithDescription("Total number of messages received through Send that were delivered to a peer stream on this node or published to the dispatcher"),
	)
	if err != nil {
		return nil, err
	}

	sendFailures, err := meter.Int64Counter(p+"send_failures_total",
		metric.WithDescription("Total number of messages received through Send that could not be delivered or published"),
	)
	if err != nil {
		return nil, err
	}

	sendInflight, err := meter.Int64UpDownCounter(p+"send_inflight",
		metric.WithDescription("Number of Send requests currently being processed"),
	)
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

		MessagesReceived: messagesReceived,
		MessageSize:      messageSize,
		ProbeMessages:    probeMessages,
		SendSuccess:      sendSuccess,
		SendFailures:     sendFailures,
		SendInflight:     sendInflight,
	}, nil
}

func getMessageSizeBucketBoundaries() []float64 {
	return []float64{
		100,
		250,
		500,
		1000,
		5000,
		10000,
		50000,
		100000,
		500000,
		1000000,
	}
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
