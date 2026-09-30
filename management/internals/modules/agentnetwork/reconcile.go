package agentnetwork

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	goproto "google.golang.org/protobuf/proto"

	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// syntheticMapping pairs a synthesised proxy mapping with the address of the
// proxy that serves it. The cluster is recorded rather than derived from the
// mapping's domain: ProxyMapping does not carry it, and the previous derivation
// -- everything after the first DNS label -- is wrong whenever the service's
// domain is not one label under its proxy's address, which silently addressed
// updates to a cluster no proxy declares.
type syntheticMapping struct {
	mapping *proto.ProxyMapping
	cluster string
}

// reconcile recomputes the synthesised reverse-proxy services for an
// account, diffs them against the previously-synthesised set in the
// in-memory cache, and emits Create / Update / Delete proxy mappings
// to the affected clusters. Also triggers a peer-side network-map
// recompute via accountManager.UpdateAccountPeers so the
// private-service ACL injection picks up the new state immediately.
//
// Reconcile failures are logged and swallowed — the underlying CRUD
// has already completed, and the next mutation (or proxy reconnect)
// will re-converge the cluster's view.
func (m *managerImpl) reconcile(ctx context.Context, accountID string) {
	if accountID == "" {
		return
	}

	defer func() {
		if m.accountManager != nil {
			m.accountManager.UpdateAccountPeers(ctx, accountID, types.UpdateReason{
				Resource:  types.UpdateResourceService,
				Operation: types.UpdateOperationUpdate,
			})
		}
	}()

	if m.proxyController == nil {
		return
	}

	services, err := SynthesizeServices(ctx, m.store, accountID)
	if err != nil {
		log.WithContext(ctx).WithError(err).Warnf("agent-network reconcile: synthesise services for account %s", accountID)
		return
	}

	oidcCfg := m.proxyController.GetOIDCValidationConfig()
	current := make(map[string]syntheticMapping, len(services))
	for _, svc := range services {
		if svc == nil || svc.ID == "" {
			continue
		}
		current[svc.ID] = syntheticMapping{
			mapping: svc.ToProtoMapping(rpservice.Update, "", oidcCfg),
			cluster: svc.ProxyCluster,
		}
	}

	m.reconcileMu.Lock()
	if m.gatewayRemovedLocked(accountID) {
		// The account is being deleted: its rows can still be read, but the
		// gateway RemoveAccountGateway took down must not come back.
		current = nil
	}
	previous := m.reconcileCache[accountID]
	if previous == nil {
		previous = make(map[string]syntheticMapping)
	}

	creates, updates, deletes := diffMappings(previous, current)
	if len(current) == 0 {
		delete(m.reconcileCache, accountID)
	} else {
		m.reconcileCache[accountID] = current
	}
	m.reconcileMu.Unlock()

	// Sent outside the lock: a CREATED or MODIFIED send stores a one-time
	// token per proxy, which can be a Redis round trip.
	m.sendMappings(ctx, accountID, creates, proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED)
	m.sendMappings(ctx, accountID, updates, proto.ProxyMappingUpdateType_UPDATE_TYPE_MODIFIED)
	m.sendMappings(ctx, accountID, deletes, proto.ProxyMappingUpdateType_UPDATE_TYPE_REMOVED)
}

// sendMappings sends each entry as updateType. It sends a copy: the entries'
// mappings are shared with reconcileCache, which another reconcile or
// RemoveAccountGateway may be reading, so they are never written.
func (m *managerImpl) sendMappings(ctx context.Context, accountID string, entries []syntheticMapping, updateType proto.ProxyMappingUpdateType) {
	for _, entry := range entries {
		update := goproto.Clone(entry.mapping).(*proto.ProxyMapping)
		update.Type = updateType
		m.proxyController.SendServiceUpdateToCluster(ctx, accountID, update, entry.cluster)
	}
}

// gatewayRemovalTTL is how long reconcile keeps a removed gateway down: far
// longer than an account deletion takes after its hooks have run.
const gatewayRemovalTTL = 5 * time.Minute

// gatewayRemovedLocked reports whether RemoveAccountGateway took the account's
// gateway down within gatewayRemovalTTL, dropping an expired mark. The caller
// holds reconcileMu.
func (m *managerImpl) gatewayRemovedLocked(accountID string) bool {
	until, ok := m.removedGateways[accountID]
	if !ok {
		return false
	}
	if time.Now().Before(until) {
		return true
	}
	delete(m.removedGateways, accountID)
	return false
}

// RemoveAccountGateway tells the proxies to drop every mapping of the account's
// gateway, so a deleted account's proxy config, provider API keys included, does
// not linger in proxy memory until the next resync. It is an account deletion
// hook: it runs before the account's data is removed, the last point at which
// the mappings can be synthesised from the store. The cache alone would miss
// them, since it is per instance and empty after a restart.
//
// Until the account's rows are gone, a reconcile triggered by a concurrent
// change would still find the gateway, so the account is marked for
// gatewayRemovalTTL and reconcile sends only removals for it meanwhile. That
// leaves two ways for the gateway to come back, which the proxy then keeps
// until its next resync: a reconcile on this instance that took its diff just
// before the mark and sends after these removals, and a reconcile on another
// management instance, which has its own mark and cache. If the deletion
// fails, the gateway stays down until the mark has expired and the account's
// next change reconciles it back.
func (m *managerImpl) RemoveAccountGateway(ctx context.Context, accountID string) error {
	if m.proxyController == nil {
		return nil
	}

	services, err := SynthesizeServices(ctx, m.store, accountID)
	if err != nil {
		return fmt.Errorf("synthesise agent network services: %w", err)
	}
	oidcCfg := m.proxyController.GetOIDCValidationConfig()
	removed := make(map[string]syntheticMapping, len(services))
	for _, svc := range services {
		if svc == nil || svc.ID == "" {
			continue
		}
		removed[svc.ID] = syntheticMapping{
			mapping: svc.ToProtoMapping(rpservice.Delete, "", oidcCfg),
			cluster: svc.ProxyCluster,
		}
	}

	// Removals carry no token, so unlike reconcile's sends these are cheap
	// enough to make under the lock, ordered with the mark.
	m.reconcileMu.Lock()
	defer m.reconcileMu.Unlock()
	for id, entry := range m.reconcileCache[accountID] {
		if _, ok := removed[id]; !ok {
			removed[id] = entry
		}
	}
	delete(m.reconcileCache, accountID)
	if m.removedGateways == nil {
		m.removedGateways = make(map[string]time.Time)
	}
	m.removedGateways[accountID] = time.Now().Add(gatewayRemovalTTL)

	entries := make([]syntheticMapping, 0, len(removed))
	for _, entry := range removed {
		entries = append(entries, entry)
	}
	m.sendMappings(ctx, accountID, entries, proto.ProxyMappingUpdateType_UPDATE_TYPE_REMOVED)
	return nil
}

// diffMappings classifies the previous→current transition for a single
// account into Create / Update / Delete sets.
//
// A change of serving proxy for the same service ID is surfaced as a Delete
// addressed to the old proxy plus a Create addressed to the new one, so the
// mapping actually moves. Comparing the recorded cluster is what makes that
// detectable: with a placement-free endpoint the mapping's domain is identical
// before and after the move, so nothing about the mapping itself reveals it.
func diffMappings(previous, current map[string]syntheticMapping) (creates, updates, deletes []syntheticMapping) {
	for id, cur := range current {
		prev, existed := previous[id]
		switch {
		case !existed:
			creates = append(creates, cur)
		case prev.mapping.GetDomain() == "" ||
			cur.mapping.GetAccountId() == prev.mapping.GetAccountId() && prev.cluster != cur.cluster:
			deletes = append(deletes, prev)
			creates = append(creates, cur)
		default:
			updates = append(updates, cur)
		}
	}
	for id, prev := range previous {
		if _, stillThere := current[id]; !stillThere {
			deletes = append(deletes, prev)
		}
	}
	return creates, updates, deletes
}
