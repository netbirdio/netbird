package agentnetwork

import (
	"context"

	log "github.com/sirupsen/logrus"

	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

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
	current := make(map[string]*proto.ProxyMapping, len(services))
	for _, svc := range services {
		if svc == nil || svc.ID == "" {
			continue
		}
		current[svc.ID] = svc.ToProtoMapping(rpservice.Update, "", oidcCfg)
	}

	m.reconcileMu.Lock()
	previous := m.reconcileCache[accountID]
	if previous == nil {
		previous = make(map[string]*proto.ProxyMapping)
	}

	creates, updates, deletes := diffMappings(previous, current)
	if len(current) == 0 {
		delete(m.reconcileCache, accountID)
	} else {
		m.reconcileCache[accountID] = current
	}
	m.reconcileMu.Unlock()

	for _, mapping := range creates {
		mapping.Type = proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED
		m.proxyController.SendServiceUpdateToCluster(ctx, accountID, mapping, clusterFromMapping(mapping))
	}
	for _, mapping := range updates {
		mapping.Type = proto.ProxyMappingUpdateType_UPDATE_TYPE_MODIFIED
		m.proxyController.SendServiceUpdateToCluster(ctx, accountID, mapping, clusterFromMapping(mapping))
	}
	for _, mapping := range deletes {
		mapping.Type = proto.ProxyMappingUpdateType_UPDATE_TYPE_REMOVED
		m.proxyController.SendServiceUpdateToCluster(ctx, accountID, mapping, clusterFromMapping(mapping))
	}
}

// diffMappings classifies the previous→current transition for a
// single account into Create / Update / Delete sets.
//
// Cluster moves (current.cluster != previous.cluster) are surfaced as
// a Delete on the old cluster + Create on the new — handled by
// emitting both a delete (on previous mapping) and a create (on the
// current mapping) for that service ID.
func diffMappings(previous, current map[string]*proto.ProxyMapping) (creates, updates, deletes []*proto.ProxyMapping) {
	for id, cur := range current {
		prev, existed := previous[id]
		switch {
		case !existed:
			creates = append(creates, cur)
		case prev.GetDomain() == "" || cur.GetAccountId() == prev.GetAccountId() && currentClusterChanged(prev, cur):
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

func currentClusterChanged(prev, cur *proto.ProxyMapping) bool {
	return clusterFromMapping(prev) != clusterFromMapping(cur)
}

// clusterFromMapping returns the cluster the mapping should be sent
// to. ProxyMapping doesn't carry the cluster directly, so we rely on
// the synthesised service's domain (`<slug>.<cluster>`) and split on
// the first '.'.
func clusterFromMapping(m *proto.ProxyMapping) string {
	if m == nil {
		return ""
	}
	domain := m.GetDomain()
	for i := 0; i < len(domain); i++ {
		if domain[i] == '.' {
			return domain[i+1:]
		}
	}
	return ""
}
