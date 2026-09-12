package manager

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/metric"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
)

// store defines the interface for proxy persistence operations
type store interface {
	SaveProxy(ctx context.Context, p *proxy.Proxy) error
	DisconnectProxy(ctx context.Context, proxyID, sessionID string) error
	DeleteProxy(ctx context.Context, proxyID, sessionID string) error
	UpdateProxyHeartbeat(ctx context.Context, p *proxy.Proxy) error
	GetActiveProxyClusterAddresses(ctx context.Context) ([]string, error)
	GetActiveProxyClusterAddressesForAccount(ctx context.Context, accountID string) ([]string, error)
	GetProxyClusters(ctx context.Context, accountID string) ([]proxy.Cluster, error)
	GetClusterSupportsCustomPorts(ctx context.Context, clusterAddr string) *bool
	GetClusterRequireSubdomain(ctx context.Context, clusterAddr string) *bool
	GetClusterSupportsCrowdSec(ctx context.Context, clusterAddr string) *bool
	GetClusterSupportsPrivate(ctx context.Context, clusterAddr string) *bool
	CleanupStaleProxies(ctx context.Context, inactivityDuration time.Duration) error
	GetProxyByAccountID(ctx context.Context, accountID string) (*proxy.Proxy, error)
	CountProxiesByAccountID(ctx context.Context, accountID string) (int64, error)
	IsClusterAddressConflicting(ctx context.Context, clusterAddress, accountID string) (bool, error)
	HasGatewayPinnedByOtherAccount(ctx context.Context, host, accountID string) (bool, error)
	DeleteAccountCluster(ctx context.Context, clusterAddress, accountID string) error
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
func (m *Manager) Connect(ctx context.Context, proxyID, sessionID, clusterAddress, ipAddress string, accountID *string, capabilities *proxy.Capabilities) (*proxy.Proxy, error) {
	now := time.Now()
	var caps proxy.Capabilities
	if capabilities != nil {
		caps = *capabilities
	}
	p := &proxy.Proxy{
		ID:             proxyID,
		SessionID:      sessionID,
		ClusterAddress: clusterAddress,
		IPAddress:      ipAddress,
		AccountID:      accountID,
		LastSeen:       now,
		ConnectedAt:    &now,
		Status:         proxy.StatusConnected,
		Capabilities:   caps,
	}

	if err := m.store.SaveProxy(ctx, p); err != nil {
		log.WithContext(ctx).Errorf("failed to register proxy %s: %v", proxyID, err)
		return nil, err
	}

	if accountID != nil {
		if err := m.confirmClusterAddressClaim(ctx, p, *accountID); err != nil {
			return nil, err
		}
	}

	log.WithContext(ctx).WithFields(log.Fields{
		"proxyID":        proxyID,
		"sessionID":      sessionID,
		"clusterAddress": clusterAddress,
		"ipAddress":      ipAddress,
	}).Info("proxy connected")

	return p, nil
}

// confirmClusterAddressClaim re-asks, once the proxy's row is committed,
// whether the account may hold the address, and withdraws the row if not.
//
// The connect path checks IsClusterAddressAvailable before Connect, but that
// read and the write here are separate statements: another claim — a foreign
// proxy row, or another account's agent network gateway pin — can land in
// between, and its own check would not have seen this row yet either.
// Re-reading after the write closes that window from this side, and the
// gateway bootstrap does the same from its side: both claimants write before
// they re-read, so of two concurrent claims at least one re-reads after the
// other has committed and backs off. Each statement runs autocommit, so that
// re-read sees every commit before it on sqlite, postgres and mysql alike.
// Both may back off, which costs a reconnect; neither keeps a claim the other
// holds, which is the invariant. No lock spans the proxies and settings
// tables portably, and a claims table would be more machinery than the
// property needs.
//
// The row is withdrawn on an inconclusive re-read too: a claim that cannot be
// confirmed must not stand, and the proxy reconnects on its own.
func (m *Manager) confirmClusterAddressClaim(ctx context.Context, p *proxy.Proxy, accountID string) error {
	available, err := m.IsClusterAddressAvailable(ctx, p.ClusterAddress, accountID)
	if err == nil && available {
		return nil
	}

	if delErr := m.store.DeleteProxy(ctx, p.ID, p.SessionID); delErr != nil {
		log.WithContext(ctx).Errorf("failed to withdraw proxy %s session %s after losing the claim on %s: %v",
			p.ID, p.SessionID, p.ClusterAddress, delErr)
	}
	if err != nil {
		return fmt.Errorf("confirm claim on cluster address %s: %w", p.ClusterAddress, err)
	}
	log.WithContext(ctx).Warnf("cluster address %s was claimed while proxy %s registered for account %s, withdrawing its row",
		p.ClusterAddress, p.ID, accountID)
	return fmt.Errorf("cluster address %s: %w", p.ClusterAddress, proxy.ErrClusterAddressUnavailable)
}

// Disconnect marks a proxy as disconnected in the database.
func (m *Manager) Disconnect(ctx context.Context, proxyID, sessionID string) error {
	if err := m.store.DisconnectProxy(ctx, proxyID, sessionID); err != nil {
		log.WithContext(ctx).Errorf("failed to disconnect proxy %s session %s: %v", proxyID, sessionID, err)
		return err
	}

	log.WithContext(ctx).WithFields(log.Fields{
		"proxyID":   proxyID,
		"sessionID": sessionID,
	}).Info("proxy disconnected")

	return nil
}

// Heartbeat updates the proxy's last seen timestamp.
func (m *Manager) Heartbeat(ctx context.Context, p *proxy.Proxy) error {
	if err := m.store.UpdateProxyHeartbeat(ctx, p); err != nil {
		log.WithContext(ctx).Debugf("failed to update proxy %s heartbeat: %v", p.ID, err)
		return err
	}

	log.WithContext(ctx).Tracef("updated heartbeat for proxy %s session %s", p.ID, p.SessionID)
	m.metrics.IncrementProxyHeartbeatCount()
	return nil
}

// GetActiveClusterAddresses returns all unique cluster addresses for active proxies
func (m *Manager) GetActiveClusterAddresses(ctx context.Context) ([]string, error) {
	addresses, err := m.store.GetActiveProxyClusterAddresses(ctx)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get active proxy cluster addresses: %v", err)
		return nil, err
	}
	return addresses, nil
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

// ClusterSupportsCrowdSec returns whether all active proxies in the cluster
// have CrowdSec configured (unanimous). Returns nil when no proxy has reported capabilities.
func (m Manager) ClusterSupportsCrowdSec(ctx context.Context, clusterAddr string) *bool {
	return m.store.GetClusterSupportsCrowdSec(ctx, clusterAddr)
}

// ClusterSupportsPrivate reports whether any active proxy claims the private capability (nil = unreported).
func (m Manager) ClusterSupportsPrivate(ctx context.Context, clusterAddr string) *bool {
	return m.store.GetClusterSupportsPrivate(ctx, clusterAddr)
}

// CleanupStale removes proxies that haven't sent heartbeat in the specified duration
func (m *Manager) CleanupStale(ctx context.Context, inactivityDuration time.Duration) error {
	if err := m.store.CleanupStaleProxies(ctx, inactivityDuration); err != nil {
		log.WithContext(ctx).Errorf("failed to cleanup stale proxies: %v", err)
		return err
	}
	return nil
}

func (m *Manager) GetActiveClusterAddressesForAccount(ctx context.Context, accountID string) ([]string, error) {
	addresses, err := m.store.GetActiveProxyClusterAddressesForAccount(ctx, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get active proxy cluster addresses for account %s: %v", accountID, err)
		return nil, err
	}
	return addresses, nil
}

func (m *Manager) GetAccountProxy(ctx context.Context, accountID string) (*proxy.Proxy, error) {
	return m.store.GetProxyByAccountID(ctx, accountID)
}

func (m *Manager) CountAccountProxies(ctx context.Context, accountID string) (int64, error) {
	return m.store.CountProxiesByAccountID(ctx, accountID)
}

// IsClusterAddressAvailable reports whether the account may claim this cluster
// address.
//
// Two kinds of claim make an address unavailable, and both are checked here so
// that no caller can consult one and forget the other. A proxy row is the
// obvious one. An agent network gateway pinned to the address by another
// account is the second: that pin is immutable and is served by whichever
// proxy declares the address, so letting a proxy from a different account take
// it strands the pin — an account-scoped proxy never receives another
// account's mappings. An account claiming an address its own gateway is pinned
// to is the intended order, not a conflict: pin first, deploy the proxy after.
func (m *Manager) IsClusterAddressAvailable(ctx context.Context, clusterAddress, accountID string) (bool, error) {
	conflicting, err := m.store.IsClusterAddressConflicting(ctx, clusterAddress, accountID)
	if err != nil {
		return false, err
	}
	if conflicting {
		return false, nil
	}

	pinned, err := m.store.HasGatewayPinnedByOtherAccount(ctx, clusterAddress, accountID)
	if err != nil {
		return false, err
	}
	if pinned {
		log.WithContext(ctx).Infof("cluster address %s is pinned as another account's agent network gateway, refusing claim by account %s", clusterAddress, accountID)
		return false, nil
	}

	return true, nil
}

func (m *Manager) DeleteAccountCluster(ctx context.Context, clusterAddress, accountID string) error {
	if err := m.store.DeleteAccountCluster(ctx, clusterAddress, accountID); err != nil {
		log.WithContext(ctx).Errorf("failed to delete cluster %s for account %s: %v", clusterAddress, accountID, err)
		return err
	}
	return nil
}
