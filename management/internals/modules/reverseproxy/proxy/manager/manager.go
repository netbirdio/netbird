package manager

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/metric"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
)

// store defines the interface for proxy persistence operations
type store interface {
	SaveProxy(ctx context.Context, p *proxy.Proxy) error
	UpdateProxyHeartbeat(ctx context.Context, proxyID, clusterAddress, ipAddress string) error
	GetActiveProxyClusterAddresses(ctx context.Context) ([]string, error)
	GetActiveProxyClusters(ctx context.Context) ([]proxy.Cluster, error)
	GetClusterSupportsCustomPorts(ctx context.Context, clusterAddr string) *bool
	GetClusterRequireSubdomain(ctx context.Context, clusterAddr string) *bool
	CleanupStaleProxies(ctx context.Context, inactivityDuration time.Duration) error
}

// Manager handles all proxy operations
type Manager struct {
	store   store
	metrics *metrics
}

// NewManager creates a new proxy Manager
func NewManager(store store, meter metric.Meter) (*Manager, error) {
	m, err := newMetrics(meter)
	if err != nil {
		return nil, err
	}

	return &Manager{
		store:   store,
		metrics: m,
	}, nil
}

// Connect registers a new proxy connection in the database.
// capabilities may be nil for old proxies that do not report them.
func (m Manager) Connect(ctx context.Context, proxyID, clusterAddress, ipAddress string, capabilities *proxy.Capabilities) error {
	now := time.Now()
	var caps proxy.Capabilities
	if capabilities != nil {
		caps = *capabilities
	}
	p := &proxy.Proxy{
		ID:             proxyID,
		ClusterAddress: clusterAddress,
		IPAddress:      ipAddress,
		LastSeen:       now,
		ConnectedAt:    &now,
		Status:         "connected",
		Capabilities:   caps,
	}

	if err := m.store.SaveProxy(ctx, p); err != nil {
		log.WithContext(ctx).Errorf("failed to register proxy %s: %v", proxyID, err)
		return err
	}

	log.WithContext(ctx).WithFields(log.Fields{
		"proxyID":        proxyID,
		"clusterAddress": clusterAddress,
		"ipAddress":      ipAddress,
	}).Info("proxy connected")

	return nil
}

// Disconnect marks a proxy as disconnected in the database
func (m Manager) Disconnect(ctx context.Context, proxyID string) error {
	now := time.Now()
	p := &proxy.Proxy{
		ID:             proxyID,
		Status:         "disconnected",
		DisconnectedAt: &now,
		LastSeen:       now,
	}

	if err := m.store.SaveProxy(ctx, p); err != nil {
		log.WithContext(ctx).Errorf("failed to disconnect proxy %s: %v", proxyID, err)
		return err
	}

	log.WithContext(ctx).WithFields(log.Fields{
		"proxyID": proxyID,
	}).Info("proxy disconnected")

	return nil
}

// Heartbeat updates the proxy's last seen timestamp
func (m Manager) Heartbeat(ctx context.Context, proxyID, clusterAddress, ipAddress string) error {
	if err := m.store.UpdateProxyHeartbeat(ctx, proxyID, clusterAddress, ipAddress); err != nil {
		log.WithContext(ctx).Debugf("failed to update proxy %s heartbeat: %v", proxyID, err)
		return err
	}

	log.WithContext(ctx).Tracef("updated heartbeat for proxy %s", proxyID)
	m.metrics.IncrementProxyHeartbeatCount()
	return nil
}

// GetActiveClusterAddresses returns all unique cluster addresses for active proxies
func (m Manager) GetActiveClusterAddresses(ctx context.Context) ([]string, error) {
	addresses, err := m.store.GetActiveProxyClusterAddresses(ctx)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get active proxy cluster addresses: %v", err)
		return nil, err
	}
	return addresses, nil
}

// GetActiveClusters returns all active proxy clusters with their connected proxy count.
func (m Manager) GetActiveClusters(ctx context.Context) ([]proxy.Cluster, error) {
	clusters, err := m.store.GetActiveProxyClusters(ctx)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get active proxy clusters: %v", err)
		return nil, err
	}
	return clusters, nil
}

// ClusterSupportsCustomPorts returns whether any active proxy in the cluster
// supports custom ports. Returns nil when no proxy has reported capabilities.
func (m Manager) ClusterSupportsCustomPorts(ctx context.Context, clusterAddr string) *bool {
	return m.store.GetClusterSupportsCustomPorts(ctx, clusterAddr)
}

// ClusterRequireSubdomain returns whether any active proxy in the cluster
// requires a subdomain. Returns nil when no proxy has reported capabilities.
func (m Manager) ClusterRequireSubdomain(ctx context.Context, clusterAddr string) *bool {
	return m.store.GetClusterRequireSubdomain(ctx, clusterAddr)
}

// CleanupStale removes proxies that haven't sent heartbeat in the specified duration
func (m Manager) CleanupStale(ctx context.Context, inactivityDuration time.Duration) error {
	if err := m.store.CleanupStaleProxies(ctx, inactivityDuration); err != nil {
		log.WithContext(ctx).Errorf("failed to cleanup stale proxies: %v", err)
		return err
	}
	return nil
}
