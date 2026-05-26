package server

import (
	"context"

	log "github.com/sirupsen/logrus"

	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
)

// collectPeerChangeAffectedGroups walks policies, routes, nameservers, DNS settings,
// and network routers to collect all group IDs and direct peer IDs affected by the
// changed groups and/or changed peers. Each collection is fetched from the store exactly once.
func collectPeerChangeAffectedGroups(ctx context.Context, transaction store.Store, accountID string, changedGroupIDs, changedPeerIDs []string) (allGroupIDs []string, directPeerIDs []string) {
	if len(changedGroupIDs) == 0 && len(changedPeerIDs) == 0 {
		return nil, nil
	}

	changedGroupSet := toSet(changedGroupIDs)
	changedPeerSet := toSet(changedPeerIDs)

	groupSet := make(map[string]struct{})
	peerSet := make(map[string]struct{})

	collectAffectedFromPolicies(ctx, transaction, accountID, changedGroupSet, changedPeerSet, groupSet, peerSet)
	collectAffectedFromRoutes(ctx, transaction, accountID, changedGroupSet, changedPeerSet, groupSet, peerSet)
	collectAffectedFromNameServers(ctx, transaction, accountID, changedGroupSet, groupSet)
	collectAffectedFromDNSSettings(ctx, transaction, accountID, changedGroupSet, groupSet)
	collectAffectedFromNetworkRouters(ctx, transaction, accountID, changedGroupSet, changedPeerSet, groupSet, peerSet)
	collectAffectedFromProxyServices(ctx, transaction, accountID, changedGroupSet, changedPeerSet, peerSet)

	allGroupIDs = setToSlice(groupSet)
	directPeerIDs = setToSlice(peerSet)

	log.WithContext(ctx).Tracef("affected groups resolution: changedGroups=%v changedPeers=%v -> affectedGroups=%v, directPeers=%v",
		changedGroupIDs, changedPeerIDs, allGroupIDs, directPeerIDs)

	return allGroupIDs, directPeerIDs
}

// collectGroupChangeAffectedGroups is a convenience wrapper used by callers that only have changed groups.
func collectGroupChangeAffectedGroups(ctx context.Context, transaction store.Store, accountID string, changedGroupIDs []string) ([]string, []string) {
	return collectPeerChangeAffectedGroups(ctx, transaction, accountID, changedGroupIDs, nil)
}

func collectAffectedFromPolicies(ctx context.Context, transaction store.Store, accountID string, changedGroupSet, changedPeerSet map[string]struct{}, groupSet, peerSet map[string]struct{}) {
	policies, err := transaction.GetAccountPolicies(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get policies for affected group resolution: %v", err)
		return
	}

	for _, policy := range policies {
		matchedByGroup := policyReferencesGroups(policy, changedGroupSet)
		matchedByPeer := len(changedPeerSet) > 0 && policyReferencesDirectPeers(policy, changedPeerSet)
		if !matchedByGroup && !matchedByPeer {
			continue
		}
		addAllToSet(groupSet, policy.RuleGroups())
		collectPolicyDirectPeers(policy, peerSet)
	}
}

func collectAffectedFromRoutes(ctx context.Context, transaction store.Store, accountID string, changedGroupSet, changedPeerSet map[string]struct{}, groupSet, peerSet map[string]struct{}) {
	routes, err := transaction.GetAccountRoutes(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get routes for affected group resolution: %v", err)
		return
	}

	for _, r := range routes {
		matchedByGroup := routeReferencesGroups(r, changedGroupSet)
		matchedByPeer := r.Peer != "" && len(changedPeerSet) > 0 && isInSet(r.Peer, changedPeerSet)
		if !matchedByGroup && !matchedByPeer {
			continue
		}
		addAllToSet(groupSet, r.Groups, r.PeerGroups, r.AccessControlGroups)
		if r.Peer != "" {
			peerSet[r.Peer] = struct{}{}
		}
	}
}

func collectAffectedFromNameServers(ctx context.Context, transaction store.Store, accountID string, changedGroupSet map[string]struct{}, groupSet map[string]struct{}) {
	if len(changedGroupSet) == 0 {
		return
	}

	nsGroups, err := transaction.GetAccountNameServerGroups(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get nameserver groups for affected group resolution: %v", err)
		return
	}

	for _, ns := range nsGroups {
		if anyInSet(ns.Groups, changedGroupSet) {
			addAllToSet(groupSet, ns.Groups)
		}
	}
}

func collectAffectedFromDNSSettings(ctx context.Context, transaction store.Store, accountID string, changedGroupSet map[string]struct{}, groupSet map[string]struct{}) {
	if len(changedGroupSet) == 0 {
		return
	}

	dnsSettings, err := transaction.GetAccountDNSSettings(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get DNS settings for affected group resolution: %v", err)
		return
	}

	for _, gID := range dnsSettings.DisabledManagementGroups {
		if _, ok := changedGroupSet[gID]; ok {
			groupSet[gID] = struct{}{}
		}
	}
}

func collectAffectedFromNetworkRouters(ctx context.Context, transaction store.Store, accountID string, changedGroupSet, changedPeerSet map[string]struct{}, groupSet, peerSet map[string]struct{}) {
	routers, err := transaction.GetNetworkRoutersByAccountID(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get network routers for affected group resolution: %v", err)
		return
	}

	for _, router := range routers {
		matchedByGroup := routerReferencesGroups(router, changedGroupSet)
		matchedByPeer := router.Peer != "" && len(changedPeerSet) > 0 && isInSet(router.Peer, changedPeerSet)
		if !matchedByGroup && !matchedByPeer {
			continue
		}
		addAllToSet(groupSet, router.PeerGroups)
		if router.Peer != "" {
			peerSet[router.Peer] = struct{}{}
		}
	}
}

// collectAffectedFromProxyServices handles policies that are synthesized at
// network-map computation time by Account.InjectProxyPolicies. Those policies
// connect proxy peers (peer.ProxyMeta.Embedded == true) to service targets and
// never reach the database, so the other collectors cannot see them.
func collectAffectedFromProxyServices(ctx context.Context, transaction store.Store, accountID string, changedGroupSet, changedPeerSet map[string]struct{}, peerSet map[string]struct{}) {
	if len(changedGroupSet) == 0 && len(changedPeerSet) == 0 {
		return
	}

	services, err := transaction.GetAccountServices(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get services for affected group resolution: %v", err)
		return
	}
	if len(services) == 0 {
		return
	}

	proxyByCluster, err := transaction.GetEmbeddedProxyPeerIDsByCluster(ctx, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get embedded proxy peers for affected group resolution: %v", err)
		return
	}
	if len(proxyByCluster) == 0 {
		return
	}

	expandedPeerSet := changedPeerSet
	expanded := false
	expand := func() {
		if expanded {
			return
		}
		expanded = true
		if len(changedGroupSet) == 0 {
			return
		}
		ids, err := transaction.GetPeerIDsByGroups(ctx, accountID, setToSlice(changedGroupSet))
		if err != nil {
			log.WithContext(ctx).Errorf("failed to expand changed groups to peers for service resolution: %v", err)
			return
		}
		if len(ids) == 0 {
			return
		}

		merged := make(map[string]struct{}, len(changedPeerSet)+len(ids))
		for id := range changedPeerSet {
			merged[id] = struct{}{}
		}
		for _, id := range ids {
			merged[id] = struct{}{}
		}
		expandedPeerSet = merged
	}

	for _, svc := range services {
		if svc == nil {
			continue
		}

		proxyPeers := proxyByCluster[svc.ProxyCluster]
		if len(proxyPeers) == 0 {
			continue
		}

		expand()

		matched := false

		for _, pid := range proxyPeers {
			if _, ok := expandedPeerSet[pid]; ok {
				matched = true
				break
			}
		}

		if !matched {
			for _, target := range svc.Targets {
				if target.TargetType != rpservice.TargetTypePeer || target.TargetId == "" {
					continue
				}
				if _, ok := expandedPeerSet[target.TargetId]; ok {
					matched = true
					break
				}
			}
		}

		if !matched {
			continue
		}

		log.WithContext(ctx).Tracef("collectAffectedFromProxyServices: service %s (cluster=%s) matched; folding %d proxy peers and target peers",
			svc.ID, svc.ProxyCluster, len(proxyPeers))

		for _, pid := range proxyPeers {
			peerSet[pid] = struct{}{}
		}
		for _, target := range svc.Targets {
			if target.TargetType == rpservice.TargetTypePeer && target.TargetId != "" {
				peerSet[target.TargetId] = struct{}{}
			}
		}
	}
}

func collectPolicyDirectPeers(policy *types.Policy, peerSet map[string]struct{}) {
	for _, rule := range policy.Rules {
		if rule.SourceResource.Type == types.ResourceTypePeer && rule.SourceResource.ID != "" {
			peerSet[rule.SourceResource.ID] = struct{}{}
		}
		if rule.DestinationResource.Type == types.ResourceTypePeer && rule.DestinationResource.ID != "" {
			peerSet[rule.DestinationResource.ID] = struct{}{}
		}
	}
}

func policyReferencesGroups(policy *types.Policy, groupSet map[string]struct{}) bool {
	for _, rule := range policy.Rules {
		if anyInSet(rule.Sources, groupSet) || anyInSet(rule.Destinations, groupSet) {
			return true
		}
	}
	return false
}

func policyReferencesDirectPeers(policy *types.Policy, changedSet map[string]struct{}) bool {
	for _, rule := range policy.Rules {
		if isDirectPeerInSet(rule.SourceResource, changedSet) || isDirectPeerInSet(rule.DestinationResource, changedSet) {
			return true
		}
	}
	return false
}

func isDirectPeerInSet(res types.Resource, set map[string]struct{}) bool {
	if res.Type != types.ResourceTypePeer || res.ID == "" {
		return false
	}
	_, ok := set[res.ID]
	return ok
}

func routeReferencesGroups(r *route.Route, groupSet map[string]struct{}) bool {
	return anyInSet(r.Groups, groupSet) || anyInSet(r.PeerGroups, groupSet) || anyInSet(r.AccessControlGroups, groupSet)
}

func routerReferencesGroups(router *routerTypes.NetworkRouter, groupSet map[string]struct{}) bool {
	return anyInSet(router.PeerGroups, groupSet)
}

func anyInSet(ids []string, set map[string]struct{}) bool {
	for _, id := range ids {
		if _, ok := set[id]; ok {
			return true
		}
	}
	return false
}

func isInSet(id string, set map[string]struct{}) bool {
	_, ok := set[id]
	return ok
}

func addAllToSet(set map[string]struct{}, slices ...[]string) {
	for _, s := range slices {
		for _, id := range s {
			set[id] = struct{}{}
		}
	}
}

func toSet(ids []string) map[string]struct{} {
	set := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		set[id] = struct{}{}
	}
	return set
}

func setToSlice(set map[string]struct{}) []string {
	s := make([]string, 0, len(set))
	for id := range set {
		s = append(s, id)
	}
	return s
}
