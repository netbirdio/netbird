// Package localmetrics exposes client connection state as a local
// Prometheus /metrics endpoint.
package localmetrics

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/peer"
)

// DefaultListenAddress is used when local metrics are enabled without an explicit address.
const DefaultListenAddress = "127.0.0.1:9191"

const shutdownTimeout = 3 * time.Second

// statusSource provides the connection state snapshots the collector reads on scrape.
type statusSource interface {
	GetPeerStates() []peer.State
	GetManagementState() peer.ManagementState
	GetSignalState() peer.SignalState
}

// GathererProvider returns the current client metrics gatherer, or nil when
// no engine is running. It is called on every scrape.
type GathererProvider func() prometheus.Gatherer

// Manager runs the local /metrics HTTP endpoint according to the active
// client configuration. Reconcile is safe to call on every config change.
type Manager struct {
	status        statusSource
	clientMetrics GathererProvider

	mu   sync.Mutex
	srv  *http.Server
	addr string
}

// NewManager creates a manager that serves metrics from status and
// clientMetrics and shuts down when ctx is canceled.
func NewManager(ctx context.Context, status statusSource, clientMetrics GathererProvider) *Manager {
	m := &Manager{status: status, clientMetrics: clientMetrics}
	go func() {
		<-ctx.Done()
		m.Stop()
	}()
	return m
}

// Reconcile starts, stops, or restarts the metrics endpoint to match the
// desired state. An empty addr falls back to DefaultListenAddress.
func (m *Manager) Reconcile(enabled bool, addr string) {
	if addr == "" {
		addr = DefaultListenAddress
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if !enabled {
		m.stop()
		return
	}
	if m.srv != nil && m.addr == addr {
		return
	}
	m.stop()

	registry := prometheus.NewRegistry()
	registry.MustRegister(newCollector(m.status))

	gatherers := prometheus.Gatherers{registry, prometheus.GathererFunc(func() ([]*dto.MetricFamily, error) {
		if m.clientMetrics == nil {
			return nil, nil
		}
		g := m.clientMetrics()
		if g == nil {
			return nil, nil
		}
		return g.Gather()
	})}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(gatherers, promhttp.HandlerOpts{}))

	srv := &http.Server{Addr: addr, Handler: mux}
	m.srv = srv
	m.addr = addr

	log.Infof("serving local metrics on http://%s/metrics", addr)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Errorf("failed to serve local metrics on %s: %v", addr, err)
		}
	}()
}

// Stop shuts down the metrics endpoint if it is running.
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stop()
}

// stop shuts down the running server. Callers must hold m.mu.
func (m *Manager) stop() {
	if m.srv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := m.srv.Shutdown(ctx); err != nil {
		log.Debugf("failed to shut down local metrics server: %v", err)
	}
	m.srv = nil
	m.addr = ""
}

// collector converts status recorder snapshots into Prometheus metrics at scrape time.
type collector struct {
	status statusSource

	managementConnected *prometheus.Desc
	signalConnected     *prometheus.Desc
	peersTotal          *prometheus.Desc
	peersConnected      *prometheus.Desc
	peerLatency         *prometheus.Desc
}

func newCollector(status statusSource) *collector {
	return &collector{
		status: status,
		managementConnected: prometheus.NewDesc(
			"netbird_management_connected",
			"Whether the client is connected to the management service (1 connected, 0 disconnected).",
			nil, nil,
		),
		signalConnected: prometheus.NewDesc(
			"netbird_signal_connected",
			"Whether the client is connected to the signal service (1 connected, 0 disconnected).",
			nil, nil,
		),
		peersTotal: prometheus.NewDesc(
			"netbird_peers",
			"Number of peers known to this client.",
			nil, nil,
		),
		peersConnected: prometheus.NewDesc(
			"netbird_peers_connected",
			"Number of connected peers by connection type.",
			[]string{"connection_type"}, nil,
		),
		peerLatency: prometheus.NewDesc(
			"netbird_peer_latency_seconds",
			"Round-trip latency per directly connected peer; relayed connections have no latency measurement.",
			[]string{"peer"}, nil,
		),
	}
}

// Describe implements prometheus.Collector.
func (c *collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.managementConnected
	ch <- c.signalConnected
	ch <- c.peersTotal
	ch <- c.peersConnected
	ch <- c.peerLatency
}

// Collect implements prometheus.Collector.
func (c *collector) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(c.managementConnected, prometheus.GaugeValue, boolToFloat(c.status.GetManagementState().Connected))
	ch <- prometheus.MustNewConstMetric(c.signalConnected, prometheus.GaugeValue, boolToFloat(c.status.GetSignalState().Connected))

	peers := c.status.GetPeerStates()
	ch <- prometheus.MustNewConstMetric(c.peersTotal, prometheus.GaugeValue, float64(len(peers)))

	var p2p, relayed float64
	for _, p := range peers {
		if p.ConnStatus != peer.StatusConnected {
			continue
		}
		if p.Relayed {
			relayed++
			continue
		}
		p2p++

		if latency := p.Latency.Seconds(); latency > 0 {
			ch <- prometheus.MustNewConstMetric(c.peerLatency, prometheus.GaugeValue, latency, p.FQDN)
		}
	}
	ch <- prometheus.MustNewConstMetric(c.peersConnected, prometheus.GaugeValue, p2p, "p2p")
	ch <- prometheus.MustNewConstMetric(c.peersConnected, prometheus.GaugeValue, relayed, "relay")
}

func boolToFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
