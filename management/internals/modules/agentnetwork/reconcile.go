package agentnetwork

import (
	"context"

	log "github.com/sirupsen/logrus"

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

	for _, entry := range creates {
		entry.mapping.Type = proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED
		m.proxyController.SendServiceUpdateToCluster(ctx, accountID, entry.mapping, entry.cluster)
	}
	for _, entry := range updates {
		entry.mapping.Type = proto.ProxyMappingUpdateType_UPDATE_TYPE_MODIFIED
		m.proxyController.SendServiceUpdateToCluster(ctx, accountID, entry.mapping, entry.cluster)
	}
	for _, entry := range deletes {
		entry.mapping.Type = proto.ProxyMappingUpdateType_UPDATE_TYPE_REMOVED
		m.proxyController.SendServiceUpdateToCluster(ctx, accountID, entry.mapping, entry.cluster)
	}
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
