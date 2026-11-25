package metrics

import (
	"context"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/netbirdio/netbird/shared/relay/messages"
)

const (
	idleTimeout = 30 * time.Second
)

type Metrics struct {
	metric.Meter

	TransferBytesSent    metric.Int64Counter
	TransferBytesRecv    metric.Int64Counter
	AuthenticationTime   metric.Float64Histogram
	PeerStoreTime        metric.Float64Histogram
	peerReconnections    metric.Int64Counter
	peerProtocolVersions metric.Int64Counter
	peers                metric.Int64UpDownCounter
	peerActivities       map[string]*PeerActivity
	mutexActivity        sync.Mutex
	ctx                  context.Context
}

func NewMetrics(ctx context.Context, meter metric.Meter) (*Metrics, error) {
	bytesSent, err := meter.Int64Counter("relay_transfer_sent_bytes_total",
		metric.WithDescription("Total number of bytes sent to peers"),
	)
	if err != nil {
		return nil, err
	}

	bytesRecv, err := meter.Int64Counter("relay_transfer_received_bytes_total",
		metric.WithDescription("Total number of bytes received from peers"),
	)
	if err != nil {
		return nil, err
	}

	peers, err := meter.Int64UpDownCounter("relay_peers",
		metric.WithDescription("Number of connected peers"),
	)
	if err != nil {
		return nil, err
	}

	peersActive, err := meter.Int64ObservableGauge("relay_peers_active",
		metric.WithDescription("Number of active connected peers"),
	)
	if err != nil {
		return nil, err
	}

	peersIdle, err := meter.Int64ObservableGauge("relay_peers_idle",
		metric.WithDescription("Number of idle connected peers"),
	)
	if err != nil {
		return nil, err
	}

	authTime, err := meter.Float64Histogram("relay_peer_authentication_time_milliseconds",
		metric.WithExplicitBucketBoundaries(getStandardBucketBoundaries()...),
		metric.WithDescription("Time taken to authenticate a peer"),
	)
	if err != nil {
		return nil, err
	}

	peerStoreTime, err := meter.Float64Histogram("relay_peer_store_time_milliseconds",
		metric.WithExplicitBucketBoundaries(getStandardBucketBoundaries()...),
		metric.WithDescription("Time taken to store a new peer connection"),
	)
	if err != nil {
		return nil, err
	}

	peerReconnections, err := meter.Int64Counter("relay_peer_reconnections_total",
		metric.WithDescription("Total number of times peers have reconnected and closed old connections"),
	)
	if err != nil {
		return nil, err
	}

	peerProtocolVersions, err := meter.Int64Counter("relay_peer_protocol_versions_total",
		metric.WithDescription("Total number of peer connections by advertised and selected protocol version"),
	)
	if err != nil {
		return nil, err
	}

	m := &Metrics{
		Meter:                meter,
		TransferBytesSent:    bytesSent,
		TransferBytesRecv:    bytesRecv,
		AuthenticationTime:   authTime,
		PeerStoreTime:        peerStoreTime,
		peers:                peers,
		peerReconnections:    peerReconnections,
		peerProtocolVersions: peerProtocolVersions,

		ctx:            ctx,
		peerActivities: make(map[string]*PeerActivity),
	}

	_, err = meter.RegisterCallback(
		func(ctx context.Context, o metric.Observer) error {
			active, idle := m.calculateActiveIdleConnections()
			o.ObserveInt64(peersActive, active)
			o.ObserveInt64(peersIdle, idle)
			return nil
		},
		peersActive, peersIdle,
	)
	if err != nil {
		return nil, err
	}

	return m, nil
}

// PeerConnected increments the number of connected peers and increments number of idle connections
func (m *Metrics) PeerConnected(id, transport string, activity *PeerActivity) {
	m.peers.Add(m.ctx, 1, metric.WithAttributes(attribute.String("transport", transport)))
	m.mutexActivity.Lock()
	defer m.mutexActivity.Unlock()

	m.peerActivities[id] = activity
}

// RecordAuthenticationTime measures the time taken for peer authentication
func (m *Metrics) RecordAuthenticationTime(duration time.Duration) {
	m.AuthenticationTime.Record(m.ctx, float64(duration.Nanoseconds())/1e6)
}

// RecordPeerStoreTime measures the time to store the peer in map
func (m *Metrics) RecordPeerStoreTime(duration time.Duration) {
	m.PeerStoreTime.Record(m.ctx, float64(duration.Nanoseconds())/1e6)
}

// PeerDisconnected decrements the number of connected peers and decrements number of idle or active connections
func (m *Metrics) PeerDisconnected(id, transport string, activity *PeerActivity) {
	m.peers.Add(m.ctx, -1, metric.WithAttributes(attribute.String("transport", transport)))
	m.mutexActivity.Lock()
	defer m.mutexActivity.Unlock()

	if m.peerActivities[id] == activity {
		delete(m.peerActivities, id)
	}
}

func (m *Metrics) RecordPeerReconnection() {
	m.peerReconnections.Add(m.ctx, 1)
}

// RecordProtocolVersion counts a new peer connection by the protocol version the client advertised
// and the version the server selected for it
func (m *Metrics) RecordProtocolVersion(advertised, selected messages.ProtocolVersion) {
	m.peerProtocolVersions.Add(m.ctx, 1, metric.WithAttributes(
		attribute.Int("advertised", int(advertised)),
		attribute.Int("selected", int(selected)),
	))
}

func (m *Metrics) calculateActiveIdleConnections() (int64, int64) {
	active, idle := int64(0), int64(0)
	m.mutexActivity.Lock()
	defer m.mutexActivity.Unlock()

	now := time.Now()
	for _, activity := range m.peerActivities {
		if activity.Idle(now) {
			idle++
		} else {
			active++
		}
	}
	return active, idle
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
