package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	"github.com/netbirdio/netbird/shared/management/status"
)

// GetProxyMetrics aggregates per-cluster + per-proxy counts for the
// self-hosted telemetry payload. Single round-trip via conditional
// aggregations so a large proxies table doesn't fan out into multiple
// queries.
func (s *SqlStore) GetProxyMetrics(ctx context.Context) (ProxyMetrics, error) {
	var m ProxyMetrics
	activeCutoff := time.Now().Add(-proxyActiveThreshold)

	// COUNT(DISTINCT ... CASE WHEN ...) is portable across sqlite/postgres
	// (MySQL too) and keeps the round-trip to one. proxy.StatusConnected
	// is the same string the cluster-capability queries use; the active
	// window matches the cluster-capability semantics (only proxies
	// heartbeating within ~2 * heartbeat interval count as connected).
	row := s.db.WithContext(ctx).
		Model(&proxy.Proxy{}).
		Select(
			"COUNT(DISTINCT cluster_address) AS clusters, "+
				"COUNT(DISTINCT CASE WHEN account_id IS NOT NULL THEN cluster_address END) AS clusters_byop, "+
				"COUNT(DISTINCT CASE WHEN private = ? THEN cluster_address END) AS clusters_private, "+
				"COUNT(*) AS proxies, "+
				"COUNT(CASE WHEN status = ? AND last_seen > ? THEN 1 END) AS proxies_connected",
			true,
			proxy.StatusConnected,
			activeCutoff,
		).
		Row()
	if err := row.Scan(&m.Clusters, &m.ClustersBYOP, &m.ClustersPrivate, &m.Proxies, &m.ProxiesConnected); err != nil {
		return ProxyMetrics{}, fmt.Errorf("scan proxy metrics: %w", err)
	}
	return m, nil
}

// SaveProxy saves or updates a proxy in the database
func (s *SqlStore) SaveProxy(ctx context.Context, p *proxy.Proxy) error {
	result := s.db.Save(p)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to save proxy: %v", result.Error)
		return status.Errorf(status.Internal, "failed to save proxy")
	}
	return nil
}

// DisconnectProxy marks a proxy as disconnected only if the session ID matches.
// This prevents a slow-to-close old session from overwriting a newer reconnection.
func (s *SqlStore) DisconnectProxy(ctx context.Context, proxyID, sessionID string) error {
	now := time.Now()
	result := s.db.
		Model(&proxy.Proxy{}).
		Where("id = ? AND session_id = ?", proxyID, sessionID).
		Updates(map[string]any{
			"status":          proxy.StatusDisconnected,
			"disconnected_at": now,
			"last_seen":       now,
		})
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to disconnect proxy %s session %s: %v", proxyID, sessionID, result.Error)
		return status.Errorf(status.Internal, "failed to disconnect proxy")
	}
	if result.RowsAffected == 0 {
		log.WithContext(ctx).Debugf("proxy %s session %s: no row updated (superseded by newer session)", proxyID, sessionID)
	}
	return nil
}

// GetAllProxies returns all reverse proxy instance rows.
func (s *SqlStore) GetAllProxies(ctx context.Context) ([]*proxy.Proxy, error) {
	var proxies []*proxy.Proxy
	result := s.db.Order("cluster_address, id").Find(&proxies)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get proxies: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get proxies")
	}
	return proxies, nil
}

// DisconnectAllProxies force-marks every proxy that is not already disconnected
// as disconnected, regardless of session ID. Unlike DisconnectProxy it is not
// session-guarded: it is an administrative repair helper, not part of the
// connection lifecycle. last_seen is left untouched so the stale-proxy reaper
// keeps working off the real last heartbeat. Returns the number of proxies updated.
func (s *SqlStore) DisconnectAllProxies(ctx context.Context) (int64, error) {
	result := s.db.
		Model(&proxy.Proxy{}).
		Where("status != ?", proxy.StatusDisconnected).
		Updates(map[string]any{
			"status":          proxy.StatusDisconnected,
			"disconnected_at": time.Now(),
		})
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to disconnect all proxies: %v", result.Error)
		return 0, status.Errorf(status.Internal, "failed to disconnect all proxies")
	}
	return result.RowsAffected, nil
}

// UpdateProxyHeartbeat updates the last_seen timestamp for the proxy's current session.
func (s *SqlStore) UpdateProxyHeartbeat(ctx context.Context, p *proxy.Proxy) error {
	now := time.Now()

	result := s.db.
		Model(&proxy.Proxy{}).
		Where("id = ? AND session_id = ?", p.ID, p.SessionID).
		Updates(map[string]any{
			"last_seen":       now,
			"status":          proxy.StatusConnected,
			"disconnected_at": nil,
		})

	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to update proxy heartbeat: %v", result.Error)
		return status.Errorf(status.Internal, "failed to update proxy heartbeat")
	}

	if result.RowsAffected == 0 {
		p.LastSeen = now
		p.ConnectedAt = &now
		p.Status = proxy.StatusConnected
		if err := s.db.Create(p).Error; err != nil {
			log.WithContext(ctx).Debugf("proxy %s session %s: heartbeat fallback insert skipped: %v", p.ID, p.SessionID, err)
		}
	}

	return nil
}

// GetActiveProxyClusterAddresses returns the unique cluster addresses of active
// shared proxies (those without an account scope). BYOP cluster addresses are
// excluded; use GetActiveProxyClusterAddressesForAccount to retrieve them.
func (s *SqlStore) GetActiveProxyClusterAddresses(ctx context.Context) ([]string, error) {
	var addresses []string

	result := s.db.
		Model(&proxy.Proxy{}).
		Where("account_id IS NULL AND status = ? AND last_seen > ?", proxy.StatusConnected, time.Now().Add(-proxyActiveThreshold)).
		Distinct("cluster_address").
		Pluck("cluster_address", &addresses)

	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get active proxy cluster addresses: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get active proxy cluster addresses")
	}

	return addresses, nil
}

func (s *SqlStore) GetActiveProxyClusterAddressesForAccount(ctx context.Context, accountID string) ([]string, error) {
	var addresses []string

	result := s.db.
		Model(&proxy.Proxy{}).
		Where("account_id = ? AND status = ? AND last_seen > ?", accountID, proxy.StatusConnected, time.Now().Add(-proxyActiveThreshold)).
		Distinct("cluster_address").
		Pluck("cluster_address", &addresses)

	if result.Error != nil {
		return nil, status.Errorf(status.Internal, "failed to get active proxy cluster addresses for account")
	}

	return addresses, nil
}

func (s *SqlStore) GetProxyByAccountID(ctx context.Context, accountID string) (*proxy.Proxy, error) {
	var p proxy.Proxy
	result := s.db.Where("account_id = ?", accountID).Take(&p)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "proxy not found for account")
		}
		return nil, status.Errorf(status.Internal, "get proxy by account ID: %v", result.Error)
	}
	return &p, nil
}

func (s *SqlStore) CountProxiesByAccountID(ctx context.Context, accountID string) (int64, error) {
	var count int64
	result := s.db.Model(&proxy.Proxy{}).Where("account_id = ?", accountID).Count(&count)
	if result.Error != nil {
		return 0, status.Errorf(status.Internal, "count proxies by account ID: %v", result.Error)
	}
	return count, nil
}

// HasActiveProxyAtClusterAddress reports whether any proxy — shared or
// account-scoped — is currently active at the given cluster address, using
// the same connected-within-threshold window as the other active-proxy
// queries. Backs the agent-network settings delete guard: settings cannot be
// deleted while a proxy declares the endpoint hostname as its address.
//
// The comparison folds case on both sides: the caller passes a normalized
// (lowercase) hostname, but proxies declare their cluster address verbatim
// and Connect stores it unchanged, so on case-sensitive collations a proxy
// declaring "GW.Example.com" would otherwise slip past the guard. Hostnames
// are case-insensitive per RFC 4343; the guard must be too.
func (s *SqlStore) HasActiveProxyAtClusterAddress(ctx context.Context, clusterAddress string) (bool, error) {
	var count int64
	result := s.db.
		Model(&proxy.Proxy{}).
		Where("LOWER(cluster_address) = LOWER(?) AND status = ? AND last_seen > ?", clusterAddress, proxy.StatusConnected, time.Now().Add(-proxyActiveThreshold)).
		Count(&count)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to count active proxies at cluster address: %v", result.Error)
		return false, status.Errorf(status.Internal, "failed to count active proxies at cluster address")
	}
	return count > 0, nil
}

func (s *SqlStore) IsClusterAddressConflicting(ctx context.Context, clusterAddress, accountID string) (bool, error) {
	var count int64
	result := s.db.
		Model(&proxy.Proxy{}).
		Where("cluster_address = ? AND (account_id IS NULL OR account_id != ?)", clusterAddress, accountID).
		Count(&count)
	if result.Error != nil {
		return false, status.Errorf(status.Internal, "check cluster address conflict: %v", result.Error)
	}
	return count > 0, nil
}

// HasForeignAccountProxyAtHost reports whether a proxy owned by a different
// account declares this host. Shared proxies (account_id IS NULL) are not
// foreign: a shared cluster is what most accounts pin their agent network
// gateway to. The match folds case because proxies declare their address as
// the operator spelled it while the caller's host is normalised; that costs a
// scan of the proxies table, taken once per account when its gateway is
// bootstrapped, not on the per-connect path IsClusterAddressConflicting serves.
func (s *SqlStore) HasForeignAccountProxyAtHost(ctx context.Context, host, accountID string) (bool, error) {
	var count int64
	result := s.db.
		Model(&proxy.Proxy{}).
		Where("LOWER(cluster_address) = LOWER(?) AND account_id IS NOT NULL AND account_id != ?", host, accountID).
		Count(&count)
	if result.Error != nil {
		return false, status.Errorf(status.Internal, "check proxy host ownership: %v", result.Error)
	}
	return count > 0, nil
}

func (s *SqlStore) DeleteAccountCluster(ctx context.Context, clusterAddress, accountID string) error {
	result := s.db.
		Where("cluster_address = ? AND account_id = ?", clusterAddress, accountID).
		Delete(&proxy.Proxy{})
	if result.Error != nil {
		return status.Errorf(status.Internal, "delete account cluster: %v", result.Error)
	}
	if result.RowsAffected == 0 {
		return status.Errorf(status.NotFound, "cluster not found")
	}
	return nil
}

// GetProxyClusters returns every cluster the account can see (shared
// plus its own BYOP), regardless of whether any proxy in the cluster
// is currently heartbeating. Online and ConnectedProxies are derived
// from the 2-min active window so the dashboard can render offline
// clusters distinctly; the 1-hour heartbeat reaper still removes rows
// that go quiet for too long.
//
// AccountOwned is determined by whether any proxy row in the group
// carries a non-NULL account_id; the caller maps that to Cluster.Type.
// Capability flags are NOT filled here — the handler enriches them via
// the per-cluster capability lookups.
func (s *SqlStore) GetProxyClusters(ctx context.Context, accountID string) ([]proxy.Cluster, error) {
	activeCutoff := time.Now().Add(-proxyActiveThreshold)

	type clusterRow struct {
		ID               string
		Address          string
		ConnectedProxies int
		Online           bool
		AccountOwned     bool
	}

	var rows []clusterRow
	result := s.db.Model(&proxy.Proxy{}).
		Select(
			"MIN(id) AS id, "+
				"cluster_address AS address, "+
				// COUNT(CASE WHEN ... THEN 1 END) counts only non-NULL — i.e. only
				// rows that satisfy the predicate — so it works portably across
				// sqlite/postgres/mysql without dialect-specific FILTER syntax.
				"COUNT(CASE WHEN status = ? AND last_seen > ? THEN 1 END) AS connected_proxies, "+
				// MAX(CASE …) > 0 expresses BOOL_OR in a way Postgres tolerates
				// (Postgres can't MAX a boolean column).
				"MAX(CASE WHEN status = ? AND last_seen > ? THEN 1 ELSE 0 END) > 0 AS online, "+
				"MAX(CASE WHEN account_id IS NOT NULL THEN 1 ELSE 0 END) > 0 AS account_owned",
			proxy.StatusConnected, activeCutoff,
			proxy.StatusConnected, activeCutoff,
		).
		Where("account_id IS NULL OR account_id = ?", accountID).
		Group("cluster_address").
		Scan(&rows)

	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get proxy clusters: %v", result.Error)
		return nil, status.Errorf(status.Internal, "get proxy clusters")
	}

	clusters := make([]proxy.Cluster, 0, len(rows))
	for _, r := range rows {
		c := proxy.Cluster{
			ID:               r.ID,
			Address:          r.Address,
			Online:           r.Online,
			ConnectedProxies: r.ConnectedProxies,
		}
		if r.AccountOwned {
			c.Type = proxy.ClusterTypeAccount
		} else {
			c.Type = proxy.ClusterTypeShared
		}
		clusters = append(clusters, c)
	}

	return clusters, nil
}

// proxyActiveThreshold is the maximum age of a heartbeat for a proxy to be
// considered active. Must be at least 2x the heartbeat interval (1 min).
const proxyActiveThreshold = 2 * time.Minute

var validCapabilityColumns = map[string]struct{}{
	"supports_custom_ports": {},
	"require_subdomain":     {},
	"supports_crowdsec":     {},
	"private":               {},
}

// GetClusterSupportsCustomPorts returns whether any active proxy in the cluster
// supports custom ports. Returns nil when no proxy reported the capability.
func (s *SqlStore) GetClusterSupportsCustomPorts(ctx context.Context, clusterAddr string) *bool {
	return s.getClusterCapability(ctx, clusterAddr, "supports_custom_ports")
}

// GetClusterRequireSubdomain returns whether any active proxy in the cluster
// requires a subdomain. Returns nil when no proxy reported the capability.
func (s *SqlStore) GetClusterRequireSubdomain(ctx context.Context, clusterAddr string) *bool {
	return s.getClusterCapability(ctx, clusterAddr, "require_subdomain")
}

// GetClusterSupportsPrivate reports whether any active proxy in the cluster
// has the private capability (nil = unreported).
func (s *SqlStore) GetClusterSupportsPrivate(ctx context.Context, clusterAddr string) *bool {
	return s.getClusterCapability(ctx, clusterAddr, "private")
}

// GetClusterSupportsCrowdSec returns whether all active proxies in the cluster
// have CrowdSec configured. Returns nil when no proxy reported the capability.
// Unlike other capabilities that use ANY-true (for rolling upgrades), CrowdSec
// requires unanimous support: a single unconfigured proxy would let requests
// bypass reputation checks.
func (s *SqlStore) GetClusterSupportsCrowdSec(ctx context.Context, clusterAddr string) *bool {
	return s.getClusterUnanimousCapability(ctx, clusterAddr, "supports_crowdsec")
}

// getClusterUnanimousCapability returns an aggregated boolean capability
// requiring all active proxies in the cluster to report true.
func (s *SqlStore) getClusterUnanimousCapability(ctx context.Context, clusterAddr, column string) *bool {
	if _, ok := validCapabilityColumns[column]; !ok {
		log.WithContext(ctx).Errorf("invalid capability column: %s", column)
		return nil
	}

	var result struct {
		Total    int64
		Reported int64
		AllTrue  bool
	}

	// All active proxies must have reported the capability (no NULLs) and all
	// must report true. A single unreported or false proxy means the cluster
	// does not unanimously support the capability.
	err := s.db.WithContext(ctx).
		Model(&proxy.Proxy{}).
		Select("COUNT(*) AS total, "+
			"COUNT(CASE WHEN "+column+" IS NOT NULL THEN 1 END) AS reported, "+
			"COUNT(*) > 0 AND COUNT(*) = COUNT(CASE WHEN "+column+" = true THEN 1 END) AS all_true").
		Where("cluster_address = ? AND status = ? AND last_seen > ?",
			clusterAddr, "connected", time.Now().Add(-proxyActiveThreshold)).
		Scan(&result).Error
	if err != nil {
		log.WithContext(ctx).Errorf("query cluster capability %s for %s: %v", column, clusterAddr, err)
		return nil
	}

	if result.Total == 0 || result.Reported == 0 {
		return nil
	}

	// If any proxy has not reported (NULL), we can't confirm unanimous support.
	if result.Reported < result.Total {
		v := false
		return &v
	}

	return &result.AllTrue
}

// getClusterCapability returns an aggregated boolean capability for the given
// cluster. It checks active (connected, recently seen) proxies and returns:
//   - *true if any proxy in the cluster has the capability set to true,
//   - *false if at least one proxy reported but none set it to true,
//   - nil if no proxy reported the capability at all.
func (s *SqlStore) getClusterCapability(ctx context.Context, clusterAddr, column string) *bool {
	if _, ok := validCapabilityColumns[column]; !ok {
		log.WithContext(ctx).Errorf("invalid capability column: %s", column)
		return nil
	}

	var result struct {
		HasCapability bool
		AnyTrue       bool
	}

	err := s.db.
		WithContext(ctx).
		Model(&proxy.Proxy{}).
		Select("COUNT(CASE WHEN "+column+" IS NOT NULL THEN 1 END) > 0 AS has_capability, "+
			"COALESCE(MAX(CASE WHEN "+column+" = true THEN 1 ELSE 0 END), 0) = 1 AS any_true").
		Where("cluster_address = ? AND status = ? AND last_seen > ?",
			clusterAddr, "connected", time.Now().Add(-proxyActiveThreshold)).
		Scan(&result).Error
	if err != nil {
		log.WithContext(ctx).Errorf("query cluster capability %s for %s: %v", column, clusterAddr, err)
		return nil
	}

	if !result.HasCapability {
		return nil
	}

	return &result.AnyTrue
}

// CleanupStaleProxies deletes proxies that haven't sent heartbeat in the specified duration
func (s *SqlStore) CleanupStaleProxies(ctx context.Context, inactivityDuration time.Duration) error {
	cutoffTime := time.Now().Add(-inactivityDuration)

	result := s.db.
		Where("last_seen < ?", cutoffTime).
		Delete(&proxy.Proxy{})

	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to cleanup stale proxies: %v", result.Error)
		return status.Errorf(status.Internal, "failed to cleanup stale proxies")
	}

	if result.RowsAffected > 0 {
		log.WithContext(ctx).Infof("Cleaned up %d stale proxies", result.RowsAffected)
	}

	return nil
}
