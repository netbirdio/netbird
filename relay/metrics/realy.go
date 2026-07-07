package metrics

import (
	"context"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	idleTimeout = 30 * time.Second
)

// peerActivity tracks a connected peer's transport and the time it was last active.
type peerActivity struct {
	transport  string
	lastActive time.Time
}

type Metrics struct {
	metric.Meter

	transferBytesSent  metric.Int64Counter
	transferBytesRecv  metric.Int64Counter
	AuthenticationTime metric.Float64Histogram
	PeerStoreTime      metric.Float64Histogram
	peerReconnections  metric.Int64Counter
	peers              metric.Int64UpDownCounter
	peerActivityChan   chan string
	peerLastActive     map[string]peerActivity
	mutexActivity      sync.Mutex
	ctx                context.Context
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

	m := &Metrics{
		Meter:              meter,
		transferBytesSent:  bytesSent,
		transferBytesRecv:  bytesRecv,
		AuthenticationTime: authTime,
		PeerStoreTime:      peerStoreTime,
		peers:              peers,
		peerReconnections:  peerReconnections,

		ctx:              ctx,
		peerActivityChan: make(chan string, 10),
		peerLastActive:   make(map[string]peerActivity),
	}

	_, err = meter.RegisterCallback(
		func(ctx context.Context, o metric.Observer) error {
			active, idle := m.calculateActiveIdleConnections()
			for transport, count := range active {
				o.ObserveInt64(peersActive, count, metric.WithAttributes(attribute.String("transport", transport)))
			}
			for transport, count := range idle {
				o.ObserveInt64(peersIdle, count, metric.WithAttributes(attribute.String("transport", transport)))
			}
			return nil
		},
		peersActive, peersIdle,
	)
	if err != nil {
		return nil, err
	}

	go m.readPeerActivity()
	return m, nil
}

// PeerConnected increments the number of connected peers and increments number of idle connections
func (m *Metrics) PeerConnected(id, transport string) {
	m.peers.Add(m.ctx, 1, metric.WithAttributes(attribute.String("transport", transport)))
	m.mutexActivity.Lock()
	defer m.mutexActivity.Unlock()

	// zero lastActive keeps the peer counted as idle until it relays its first message
	m.peerLastActive[id] = peerActivity{transport: transport}
}

// RecordBytesSent records the number of bytes relayed out to a peer over the given transport.
func (m *Metrics) RecordBytesSent(transport string, n int) {
	m.transferBytesSent.Add(m.ctx, int64(n), metric.WithAttributes(attribute.String("transport", transport)))
}

// RecordBytesRecv records the number of bytes received from a peer over the given transport.
func (m *Metrics) RecordBytesRecv(transport string, n int) {
	m.transferBytesRecv.Add(m.ctx, int64(n), metric.WithAttributes(attribute.String("transport", transport)))
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
func (m *Metrics) PeerDisconnected(id, transport string) {
	m.peers.Add(m.ctx, -1, metric.WithAttributes(attribute.String("transport", transport)))
	m.mutexActivity.Lock()
	defer m.mutexActivity.Unlock()

	delete(m.peerLastActive, id)
}

func (m *Metrics) RecordPeerReconnection() {
	m.peerReconnections.Add(m.ctx, 1)
}

// PeerActivity increases the active connections
func (m *Metrics) PeerActivity(peerID string) {
	select {
	case m.peerActivityChan <- peerID:
	default:
		log.Tracef("peer activity channel is full, dropping activity metrics for peer %s", peerID)
	}
}

// calculateActiveIdleConnections returns the number of active and idle peers grouped by transport.
func (m *Metrics) calculateActiveIdleConnections() (active, idle map[string]int64) {
	active, idle = make(map[string]int64), make(map[string]int64)
	m.mutexActivity.Lock()
	defer m.mutexActivity.Unlock()

	for _, peer := range m.peerLastActive {
		if time.Since(peer.lastActive) > idleTimeout {
			idle[peer.transport]++
		} else {
			active[peer.transport]++
		}
	}
	return active, idle
}

func (m *Metrics) readPeerActivity() {
	for {
		select {
		case peerID := <-m.peerActivityChan:
			m.mutexActivity.Lock()
			// only refresh known peers; a late activity event must not resurrect a disconnected peer
			if peer, ok := m.peerLastActive[peerID]; ok {
				peer.lastActive = time.Now()
				m.peerLastActive[peerID] = peer
			}
			m.mutexActivity.Unlock()
		case <-m.ctx.Done():
			return
		}
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
