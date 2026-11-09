package localmetrics

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/peer"
)

type stubStatus struct {
	peers      []peer.State
	management peer.ManagementState
	signal     peer.SignalState
}

func (s *stubStatus) GetPeerStates() []peer.State              { return s.peers }
func (s *stubStatus) GetManagementState() peer.ManagementState { return s.management }
func (s *stubStatus) GetSignalState() peer.SignalState         { return s.signal }

func testStatus() *stubStatus {
	return &stubStatus{
		management: peer.ManagementState{Connected: true},
		signal:     peer.SignalState{Connected: true},
		peers: []peer.State{
			{FQDN: "peer-a.netbird.cloud", IP: "100.90.0.1", ConnStatus: peer.StatusConnected, Relayed: false, Latency: 12 * time.Millisecond},
			{FQDN: "peer-b.netbird.cloud", IP: "100.90.0.2", ConnStatus: peer.StatusConnected, Relayed: false, Latency: 36 * time.Millisecond},
			{FQDN: "peer-c.netbird.cloud", IP: "100.90.0.3", ConnStatus: peer.StatusConnected, Relayed: true},
			{FQDN: "peer-d.netbird.cloud", IP: "100.90.0.4", ConnStatus: peer.StatusIdle},
		},
	}
}

func TestCollector(t *testing.T) {
	c := newCollector(testStatus())

	expected := `
# HELP netbird_management_connected Whether the client is connected to the management service (1 connected, 0 disconnected).
# TYPE netbird_management_connected gauge
netbird_management_connected 1
# HELP netbird_peer_latency_seconds Round-trip latency per directly connected peer; relayed connections have no latency measurement.
# TYPE netbird_peer_latency_seconds gauge
netbird_peer_latency_seconds{peer="peer-a.netbird.cloud"} 0.012
netbird_peer_latency_seconds{peer="peer-b.netbird.cloud"} 0.036
# HELP netbird_peers Number of peers known to this client.
# TYPE netbird_peers gauge
netbird_peers 4
# HELP netbird_peers_connected Number of connected peers by connection type.
# TYPE netbird_peers_connected gauge
netbird_peers_connected{connection_type="p2p"} 2
netbird_peers_connected{connection_type="relay"} 1
# HELP netbird_signal_connected Whether the client is connected to the signal service (1 connected, 0 disconnected).
# TYPE netbird_signal_connected gauge
netbird_signal_connected 1
`
	require.NoError(t, testutil.CollectAndCompare(c, strings.NewReader(expected)))
}

func TestServe(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "must find a free port")
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	m := NewManager(ctx, testStatus(), nil)
	m.Reconcile(true, addr)

	var body string
	require.Eventually(t, func() bool {
		resp, err := http.Get(fmt.Sprintf("http://%s/metrics", addr))
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(resp.Body)
		if err != nil || resp.StatusCode != http.StatusOK {
			return false
		}
		body = string(data)
		return true
	}, 2*time.Second, 50*time.Millisecond, "metrics endpoint should come up")

	assert.Contains(t, body, "netbird_peers 4")
	assert.Contains(t, body, `netbird_peers_connected{connection_type="relay"} 1`)
	assert.Contains(t, body, `netbird_peer_latency_seconds{peer="peer-a.netbird.cloud"} 0.012`)
}

// A server that never came up must not be remembered, otherwise reconciling the
// same address again is a no-op and the endpoint never recovers.
func TestReconcileForgetsAFailedServer(t *testing.T) {
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "must find a free port")
	t.Cleanup(func() { _ = blocker.Close() })
	addr := blocker.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	m := NewManager(ctx, testStatus(), nil)
	m.Reconcile(true, addr)

	require.Eventually(t, func() bool {
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.srv == nil && m.addr == ""
	}, 2*time.Second, 20*time.Millisecond, "the failed server should be dropped")

	require.NoError(t, blocker.Close())
	m.Reconcile(true, addr)

	require.Eventually(t, func() bool {
		resp, err := http.Get(fmt.Sprintf("http://%s/metrics", addr))
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 2*time.Second, 50*time.Millisecond, "reconciling the same address should retry the bind")
}

func TestIsLoopback(t *testing.T) {
	tests := map[string]bool{
		"":                        true,
		"127.0.0.1:9191":          true,
		"127.9.9.9:9191":          true,
		"[::1]:9191":              true,
		"[::ffff:127.0.0.1]:9191": true,
		"localhost:9191":          true,
		"0.0.0.0:9191":            false,
		"[::]:9191":               false,
		"192.168.1.10:9191":       false,
		"not-an-address":          false,
		"example.com:9191":        false,
	}

	for addr, want := range tests {
		t.Run(addr, func(t *testing.T) {
			assert.Equal(t, want, IsLoopback(addr), "loopback verdict for %q", addr)
		})
	}
}
