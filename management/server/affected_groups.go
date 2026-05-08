package server

import (
	"context"

	log "github.com/sirupsen/logrus"

	nbdns "github.com/netbirdio/netbird/dns"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
)

// collectGroupChangeAffectedGroups walks policies, routes, nameservers, DNS settings,
// and network routers to collect all group IDs and direct peer IDs affected by the changed groups.
func collectGroupChangeAffectedGroups(ctx context.Context, transaction store.Store, accountID string, changedGroupIDs []string) (allGroupIDs []string, directPeerIDs []string) {
	if len(changedGroupIDs) == 0 {
		return nil, nil
	}

	changedSet := make(map[string]struct{}, len(changedGroupIDs))
	for _, id := range changedGroupIDs {
		changedSet[id] = struct{}{}
	}

	log.WithContext(ctx).Tracef("collecting affected groups for changed groups %v", changedGroupIDs)

	groupSet := make(map[string]struct{})
	peerSet := make(map[string]struct{})

	collectPolicyAffectedGroups(ctx, transaction, accountID, changedSet, groupSet, peerSet)
	collectRouteAffectedGroups(ctx, transaction, accountID, changedSet, groupSet, peerSet)
	collectNameServerAffectedGroups(ctx, transaction, accountID, changedSet, groupSet)
	collectDNSSettingsAffectedGroups(ctx, transaction, accountID, changedSet, groupSet)
	collectNetworkRouterAffectedGroups(ctx, transaction, accountID, changedSet, groupSet, peerSet)

	allGroupIDs = make([]string, 0, len(groupSet))
	for gID := range groupSet {
		allGroupIDs = append(allGroupIDs, gID)
	}

	directPeerIDs = make([]string, 0, len(peerSet))
	for pID := range peerSet {
		directPeerIDs = append(directPeerIDs, pID)
	}

	log.WithContext(ctx).Tracef("affected groups resolution: changed=%v -> affectedGroups=%v, directPeers=%v", changedGroupIDs, allGroupIDs, directPeerIDs)

	return allGroupIDs, directPeerIDs
}

func collectPolicyAffectedGroups(ctx context.Context, transaction store.Store, accountID string, changedSet, groupSet, peerSet map[string]struct{}) {
	policies, err := transaction.GetAccountPolicies(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get policies for group change resolution: %v", err)
		return
	}

	for _, policy := range policies {
		if !policyReferencesGroups(policy, changedSet) {
			continue
		}
		ruleGroups := policy.RuleGroups()
		log.WithContext(ctx).Tracef("policy %s (%s) references changed groups, adding rule groups %v", policy.ID, policy.Name, ruleGroups)
		for _, gID := range ruleGroups {
			groupSet[gID] = struct{}{}
		}
		collectPolicyDirectPeers(policy, peerSet)
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

func collectRouteAffectedGroups(ctx context.Context, transaction store.Store, accountID string, changedSet, groupSet, peerSet map[string]struct{}) {
	routes, err := transaction.GetAccountRoutes(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get routes for group change resolution: %v", err)
		return
	}

	for _, r := range routes {
		if !routeReferencesGroups(r, changedSet) {
			continue
		}
		log.WithContext(ctx).Tracef("route %s (%s) references changed groups", r.ID, r.Description)
		addAllToSet(groupSet, r.Groups, r.PeerGroups, r.AccessControlGroups)
		if r.Peer != "" {
			peerSet[r.Peer] = struct{}{}
		}
	}
}

func collectNameServerAffectedGroups(ctx context.Context, transaction store.Store, accountID string, changedSet, groupSet map[string]struct{}) {
	nsGroups, err := transaction.GetAccountNameServerGroups(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get nameserver groups for group change resolution: %v", err)
		return
	}

	for _, ns := range nsGroups {
		if !nsReferencesGroups(ns, changedSet) {
			continue
		}
		for _, g := range ns.Groups {
			groupSet[g] = struct{}{}
		}
	}
}

func nsReferencesGroups(ns *nbdns.NameServerGroup, changedSet map[string]struct{}) bool {
	for _, gID := range ns.Groups {
		if _, ok := changedSet[gID]; ok {
			log.Tracef("nameserver group %s (%s) references changed group %s", ns.ID, ns.Name, gID)
			return true
		}
	}
	return false
}

func collectDNSSettingsAffectedGroups(ctx context.Context, transaction store.Store, accountID string, changedSet, groupSet map[string]struct{}) {
	dnsSettings, err := transaction.GetAccountDNSSettings(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get DNS settings for group change resolution: %v", err)
		return
	}

	for _, gID := range dnsSettings.DisabledManagementGroups {
		if _, ok := changedSet[gID]; ok {
			log.WithContext(ctx).Tracef("DNS disabled management group %s matches changed group", gID)
			groupSet[gID] = struct{}{}
		}
	}
}

func collectNetworkRouterAffectedGroups(ctx context.Context, transaction store.Store, accountID string, changedSet, groupSet, peerSet map[string]struct{}) {
	routers, err := transaction.GetNetworkRoutersByAccountID(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get network routers for group change resolution: %v", err)
		return
	}

	for _, router := range routers {
		if !routerReferencesGroups(router, changedSet) {
			continue
		}
		log.WithContext(ctx).Tracef("network router %s references changed groups", router.ID)
		for _, gID := range router.PeerGroups {
			groupSet[gID] = struct{}{}
		}
		if router.Peer != "" {
			log.WithContext(ctx).Tracef("network router %s has direct peer %s", router.ID, router.Peer)
			peerSet[router.Peer] = struct{}{}
		}
	}
}

// collectDirectPeerRefAffectedGroups finds entities (policies, routes, network routers) that reference
// the changed peers directly by peer ID (not via group membership) and collects the affected groups and peers.
func collectDirectPeerRefAffectedGroups(ctx context.Context, transaction store.Store, accountID string, changedPeerIDs []string) (groupIDs []string, directPeerIDs []string) {
	if len(changedPeerIDs) == 0 {
		return nil, nil
	}

	changedSet := make(map[string]struct{}, len(changedPeerIDs))
	for _, id := range changedPeerIDs {
		changedSet[id] = struct{}{}
	}

	groupSet := make(map[string]struct{})
	peerSet := make(map[string]struct{})

	collectPolicyDirectPeerRefGroups(ctx, transaction, accountID, changedSet, groupSet, peerSet)
	collectRouteDirectPeerRefGroups(ctx, transaction, accountID, changedSet, groupSet, peerSet)
	collectRouterDirectPeerRefGroups(ctx, transaction, accountID, changedSet, groupSet, peerSet)

	groupIDs = make([]string, 0, len(groupSet))
	for gID := range groupSet {
		groupIDs = append(groupIDs, gID)
	}

	directPeerIDs = make([]string, 0, len(peerSet))
	for pID := range peerSet {
		directPeerIDs = append(directPeerIDs, pID)
	}

	return groupIDs, directPeerIDs
}

func collectPolicyDirectPeerRefGroups(ctx context.Context, transaction store.Store, accountID string, changedSet, groupSet, peerSet map[string]struct{}) {
	policies, err := transaction.GetAccountPolicies(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get policies for direct peer ref resolution: %v", err)
		return
	}

	for _, policy := range policies {
		if !policyReferencesDirectPeers(policy, changedSet) {
			continue
		}
		for _, gID := range policy.RuleGroups() {
			groupSet[gID] = struct{}{}
		}
		collectPolicyDirectPeers(policy, peerSet)
	}
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

func collectRouteDirectPeerRefGroups(ctx context.Context, transaction store.Store, accountID string, changedSet, groupSet, peerSet map[string]struct{}) {
	routes, err := transaction.GetAccountRoutes(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get routes for direct peer ref resolution: %v", err)
		return
	}

	for _, r := range routes {
		if r.Peer == "" {
			continue
		}
		if _, ok := changedSet[r.Peer]; !ok {
			continue
		}
		addAllToSet(groupSet, r.Groups, r.PeerGroups, r.AccessControlGroups)
		peerSet[r.Peer] = struct{}{}
	}
}

func collectRouterDirectPeerRefGroups(ctx context.Context, transaction store.Store, accountID string, changedSet, groupSet, peerSet map[string]struct{}) {
	routers, err := transaction.GetNetworkRoutersByAccountID(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get network routers for direct peer ref resolution: %v", err)
		return
	}

	for _, router := range routers {
		if router.Peer == "" {
			continue
		}
		if _, ok := changedSet[router.Peer]; !ok {
			continue
		}
		for _, gID := range router.PeerGroups {
			groupSet[gID] = struct{}{}
		}
		peerSet[router.Peer] = struct{}{}
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

func routeReferencesGroups(r *route.Route, groupSet map[string]struct{}) bool {
	return anyInSet(r.Groups, groupSet) || anyInSet(r.PeerGroups, groupSet) || anyInSet(r.AccessControlGroups, groupSet)
}

func routerReferencesGroups(router *routerTypes.NetworkRouter, groupSet map[string]struct{}) bool {
	return anyInSet(router.PeerGroups, groupSet)
}

func addAllToSet(set map[string]struct{}, slices ...[]string) {
	for _, s := range slices {
		for _, id := range s {
			set[id] = struct{}{}
		}
	}
}
