package metrics_test

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/internal/metrics"
	"github.com/netbirdio/netbird/proxy/internal/types"
)

func gatherGauge(t *testing.T, reg *prometheus.Registry, name string, labels prometheus.Labels) float64 {
	t.Helper()
	families, err := reg.Gather()
	require.NoError(t, err)
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			if matchLabels(m.GetLabel(), labels) {
				return m.GetGauge().GetValue()
			}
		}
	}
	t.Fatalf("metric %s with labels %v not found", name, labels)
	return 0
}

func gatherCounter(t *testing.T, reg *prometheus.Registry, name string, labels prometheus.Labels) float64 {
	t.Helper()
	families, err := reg.Gather()
	require.NoError(t, err)
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			if matchLabels(m.GetLabel(), labels) {
				return m.GetCounter().GetValue()
			}
		}
	}
	t.Fatalf("metric %s with labels %v not found", name, labels)
	return 0
}

func gatherHistogramCount(t *testing.T, reg *prometheus.Registry, name string, labels prometheus.Labels) uint64 {
	t.Helper()
	families, err := reg.Gather()
	require.NoError(t, err)
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			if matchLabels(m.GetLabel(), labels) {
				return m.GetHistogram().GetSampleCount()
			}
		}
	}
	t.Fatalf("metric %s with labels %v not found", name, labels)
	return 0
}

func matchLabels(pairs []*io_prometheus_client.LabelPair, labels prometheus.Labels) bool {
	if len(pairs) != len(labels) {
		return false
	}
	for _, p := range pairs {
		if v, ok := labels[p.GetName()]; !ok || v != p.GetValue() {
			return false
		}
	}
	return true
}

func TestL4ServiceGauge(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)

	m.L4ServiceAdded(types.ServiceModeTCP)
	m.L4ServiceAdded(types.ServiceModeTCP)
	m.L4ServiceAdded(types.ServiceModeUDP)

	assert.Equal(t, float64(2), gatherGauge(t, reg, "netbird_proxy_l4_services_count", prometheus.Labels{"mode": "tcp"}))
	assert.Equal(t, float64(1), gatherGauge(t, reg, "netbird_proxy_l4_services_count", prometheus.Labels{"mode": "udp"}))

	m.L4ServiceRemoved(types.ServiceModeTCP)
	assert.Equal(t, float64(1), gatherGauge(t, reg, "netbird_proxy_l4_services_count", prometheus.Labels{"mode": "tcp"}))
}

func TestTCPRelayMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)

	acct := "acct-1"

	m.TCPRelayStarted(acct)
	m.TCPRelayStarted(acct)

	assert.Equal(t, float64(2), gatherGauge(t, reg, "netbird_proxy_tcp_active_connections", prometheus.Labels{"account_id": acct}))
	assert.Equal(t, float64(2), gatherCounter(t, reg, "netbird_proxy_tcp_connections_total", prometheus.Labels{"account_id": acct, "result": "success"}))

	m.TCPRelayEnded(acct, 10*time.Second, 1000, 500)

	assert.Equal(t, float64(1), gatherGauge(t, reg, "netbird_proxy_tcp_active_connections", prometheus.Labels{"account_id": acct}))
	assert.Equal(t, uint64(1), gatherHistogramCount(t, reg, "netbird_proxy_tcp_connection_duration_seconds", prometheus.Labels{"account_id": acct}))
	assert.Equal(t, float64(1000), gatherCounter(t, reg, "netbird_proxy_tcp_bytes_total", prometheus.Labels{"direction": "client_to_backend"}))
	assert.Equal(t, float64(500), gatherCounter(t, reg, "netbird_proxy_tcp_bytes_total", prometheus.Labels{"direction": "backend_to_client"}))

	m.TCPRelayDialError(acct)
	assert.Equal(t, float64(1), gatherCounter(t, reg, "netbird_proxy_tcp_connections_total", prometheus.Labels{"account_id": acct, "result": "dial_error"}))

	m.TCPRelayRejected(acct)
	assert.Equal(t, float64(1), gatherCounter(t, reg, "netbird_proxy_tcp_connections_total", prometheus.Labels{"account_id": acct, "result": "rejected"}))
}

func TestUDPSessionMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)

	acct := "acct-2"

	m.UDPSessionStarted(acct)
	m.UDPSessionStarted(acct)

	assert.Equal(t, float64(2), gatherGauge(t, reg, "netbird_proxy_udp_active_sessions", prometheus.Labels{"account_id": acct}))
	assert.Equal(t, float64(2), gatherCounter(t, reg, "netbird_proxy_udp_sessions_total", prometheus.Labels{"account_id": acct, "result": "success"}))

	m.UDPSessionEnded(acct)
	assert.Equal(t, float64(1), gatherGauge(t, reg, "netbird_proxy_udp_active_sessions", prometheus.Labels{"account_id": acct}))

	m.UDPSessionDialError(acct)
	assert.Equal(t, float64(1), gatherCounter(t, reg, "netbird_proxy_udp_sessions_total", prometheus.Labels{"account_id": acct, "result": "dial_error"}))

	m.UDPSessionRejected(acct)
	assert.Equal(t, float64(1), gatherCounter(t, reg, "netbird_proxy_udp_sessions_total", prometheus.Labels{"account_id": acct, "result": "rejected"}))

	m.UDPPacketRelayed(types.RelayDirectionClientToBackend, 100)
	m.UDPPacketRelayed(types.RelayDirectionClientToBackend, 200)
	m.UDPPacketRelayed(types.RelayDirectionBackendToClient, 150)

	assert.Equal(t, float64(2), gatherCounter(t, reg, "netbird_proxy_udp_packets_total", prometheus.Labels{"direction": "client_to_backend"}))
	assert.Equal(t, float64(1), gatherCounter(t, reg, "netbird_proxy_udp_packets_total", prometheus.Labels{"direction": "backend_to_client"}))
	assert.Equal(t, float64(300), gatherCounter(t, reg, "netbird_proxy_udp_bytes_total", prometheus.Labels{"direction": "client_to_backend"}))
	assert.Equal(t, float64(150), gatherCounter(t, reg, "netbird_proxy_udp_bytes_total", prometheus.Labels{"direction": "backend_to_client"}))
}
