package metrics

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestCalculateActiveIdleConnections(t *testing.T) {
	now := time.Now()
	m := &Metrics{
		peerLastActive: map[string]peerActivity{
			"ws-active-1":   {transport: "ws", lastActive: now},
			"ws-active-2":   {transport: "ws", lastActive: now.Add(-idleTimeout / 2)},
			"ws-idle-1":     {transport: "ws", lastActive: now.Add(-2 * idleTimeout)},
			"quic-active":   {transport: "quic", lastActive: now},
			"quic-idle-1":   {transport: "quic", lastActive: now.Add(-2 * idleTimeout)},
			"quic-idle-new": {transport: "quic", lastActive: time.Time{}}, // just connected, no activity yet
		},
	}

	active, idle := m.calculateActiveIdleConnections()

	assertCount(t, "active", active, map[string]int64{"ws": 2, "quic": 1})
	assertCount(t, "idle", idle, map[string]int64{"ws": 1, "quic": 2})
}

// TestCalculateActiveIdleConnectionsZeroValuedSeries checks that a transport whose peers are all in
// one state still reports a 0 in the other state, so its gauge series does not disappear.
func TestCalculateActiveIdleConnectionsZeroValuedSeries(t *testing.T) {
	m := &Metrics{
		peerLastActive: map[string]peerActivity{
			"ws-active": {transport: "ws", lastActive: time.Now()},    // ws: only active
			"quic-idle": {transport: "quic", lastActive: time.Time{}}, // quic: only idle
		},
	}

	active, idle := m.calculateActiveIdleConnections()

	assertCount(t, "active", active, map[string]int64{"ws": 1, "quic": 0})
	assertCount(t, "idle", idle, map[string]int64{"ws": 0, "quic": 1})
}

// TestTransportLabels verifies every relay peer/transfer metric is exported with a transport attribute.
func TestTransportLabels(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	meter := provider.Meter("github.com/netbirdio/netbird/relay/metrics")

	m, err := NewMetrics(ctx, meter)
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}

	m.PeerConnected("peer-ws", "ws")
	m.PeerConnected("peer-quic", "quic")
	m.RecordBytesSent("quic", 100)
	m.RecordBytesRecv("ws", 40)

	// make peer-ws count as active; peer-quic keeps its zero lastActive and stays idle
	m.mutexActivity.Lock()
	m.peerLastActive["peer-ws"] = peerActivity{transport: "ws", lastActive: time.Now()}
	m.mutexActivity.Unlock()

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("collect: %v", err)
	}

	assertCount(t, "relay_peers", byTransport(t, rm, "relay_peers"), map[string]int64{"ws": 1, "quic": 1})
	// both transports are present in both gauges; the empty buckets report 0 rather than vanishing
	assertCount(t, "relay_peers_active", byTransport(t, rm, "relay_peers_active"), map[string]int64{"ws": 1, "quic": 0})
	assertCount(t, "relay_peers_idle", byTransport(t, rm, "relay_peers_idle"), map[string]int64{"ws": 0, "quic": 1})
	assertCount(t, "relay_transfer_sent_bytes_total", byTransport(t, rm, "relay_transfer_sent_bytes_total"), map[string]int64{"quic": 100})
	assertCount(t, "relay_transfer_received_bytes_total", byTransport(t, rm, "relay_transfer_received_bytes_total"), map[string]int64{"ws": 40})
}

func assertCount(t *testing.T, name string, got, want map[string]int64) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s: got %v, want %v", name, got, want)
		return
	}
	for transport, count := range want {
		if got[transport] != count {
			t.Errorf("%s[%s]: got %d, want %d", name, transport, got[transport], count)
		}
	}
}

// byTransport returns the value of each data point of the named metric keyed by its transport attribute.
func byTransport(t *testing.T, rm metricdata.ResourceMetrics, name string) map[string]int64 {
	t.Helper()
	out := make(map[string]int64)
	for _, sm := range rm.ScopeMetrics {
		for _, mm := range sm.Metrics {
			if mm.Name != name {
				continue
			}
			switch data := mm.Data.(type) {
			case metricdata.Sum[int64]:
				for _, dp := range data.DataPoints {
					out[transportAttr(dp.Attributes)] = dp.Value
				}
			case metricdata.Gauge[int64]:
				for _, dp := range data.DataPoints {
					out[transportAttr(dp.Attributes)] = dp.Value
				}
			default:
				t.Fatalf("%s: unexpected data type %T", name, mm.Data)
			}
		}
	}
	return out
}

func transportAttr(set attribute.Set) string {
	v, _ := set.Value(attribute.Key("transport"))
	return v.AsString()
}
