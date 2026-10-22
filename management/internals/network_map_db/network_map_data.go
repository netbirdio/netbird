package networkmapdb

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"

	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/networkmap"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

// GetNetworkMapData loads the account's network-map data. A nil selectPeers
// loads every peer. Otherwise only the embedded proxy peers and the peers
// selectPeers picks are loaded: it receives the data without those peers,
// inside the load's snapshot, and returns their IDs or all to load every peer.
// PeerVersions always covers every peer of the account.
func (s *NetworkMapDBStoreImpl) GetNetworkMapData(ctx context.Context, accountId string, selectPeers func(nmd *networkmap.NetworkMapData) (peerIDs []string, all bool, err error)) (*networkmap.NetworkMapData, error) {
	type extraSettingsResult struct {
		settings *types.ExtraSettings
		err      error
	}
	extraSettingsCh := make(chan extraSettingsResult, 1)
	go func() {
		settings, err := s.ExtraSettingsManager.GetExtraSettings(ctx, accountId)
		extraSettingsCh <- extraSettingsResult{settings: settings, err: err}
	}()

	var nmd *networkmap.NetworkMapData
	var storeSelector PeerSelector
	if selectPeers != nil {
		storeSelector = func(rows *AccountRows) ([]string, bool, error) {
			nmd = newNetworkMapData(rows)
			return selectPeers(nmd)
		}
	}

	rows, err := s.Store.LoadAccount(ctx, accountId, storeSelector)
	if err != nil {
		return nil, err
	}

	if nmd == nil {
		nmd = newNetworkMapData(rows)
	} else {
		nmd.Peers = toMap(rows.Peers, func(p nmdata.Peer) string { return p.ID })
	}
	nmd.PeerVersions = rows.PeerVersions
	if nmd.PeerVersions == nil {
		nmd.PeerVersions = peerVersions(rows.Peers)
	}

	extraSettings := <-extraSettingsCh
	if extraSettings.err != nil {
		return nil, extraSettings.err
	}

	nmd.ValidatedPeers, err = s.IntegratedPeerValidator.GetValidatedPeers(ctx, accountId, maps.Values(nmd.Groups), maps.Values(nmd.Peers), extraSettings.settings)
	if err != nil {
		return nil, err
	}

	return nmd, nil
}

// LoadAccountRows implements NetworkMapDBStore.LoadAccount one query at a time
// over a transaction of store, for engines that cannot pipeline queries.
func LoadAccountRows(ctx context.Context, store NetworkMapDBStore, accountID string, selectPeers PeerSelector) (*AccountRows, error) {
	tx, err := store.BeginTx(ctx)
	if err != nil {
		return nil, err
	}

	rows, err := readAccountRows(ctx, tx, accountID, selectPeers)
	if err != nil {
		if rbErr := tx.RollbackTx(ctx); rbErr != nil {
			log.WithContext(ctx).Warnf("failed to rollback network map read transaction: %v", rbErr)
		}
		return nil, err
	}

	if err = tx.CommitTx(ctx); err != nil {
		log.WithContext(ctx).Warnf("failed to commit network map read transaction: %v", err)
	}
	return rows, nil
}

func readAccountRows(ctx context.Context, tx NetworkMapDBStoreConn, accountID string, selectPeers PeerSelector) (*AccountRows, error) {
	rows := &AccountRows{}
	var err error

	if rows.Settings, err = tx.GetAccountSettings(ctx, accountID); err != nil {
		return nil, fmt.Errorf("get account settings: %w", err)
	}
	if rows.ZoneCandidates, err = tx.GetAppliedZoneCandidates(ctx, accountID); err != nil {
		return nil, fmt.Errorf("get applied zone candidates: %w", err)
	}
	if rows.Groups, rows.ResourceToGroupIdx, err = tx.GetGroups(ctx, accountID); err != nil {
		return nil, fmt.Errorf("get groups: %w", err)
	}
	if rows.NameServerGroups, err = tx.GetNameServerGroups(ctx, accountID); err != nil {
		return nil, fmt.Errorf("get nameserver groups: %w", err)
	}
	if rows.NetworkResources, err = tx.GetNetworkResources(ctx, accountID); err != nil {
		return nil, fmt.Errorf("get network resources: %w", err)
	}
	if rows.Routers, err = tx.GetNetworkRouters(ctx, accountID); err != nil {
		return nil, fmt.Errorf("get network routers: %w", err)
	}
	if rows.Network, err = tx.GetNetwork(ctx, accountID); err != nil {
		return nil, fmt.Errorf("get network: %w", err)
	}
	if rows.Policies, rows.PolicyToDestinationResourceIdx, rows.PolicyToDestinationGroupIdx, err = tx.GetPolicies(ctx, accountID); err != nil {
		return nil, fmt.Errorf("get policies: %w", err)
	}
	if rows.PostureChecks, rows.PostureCheckXIDToPublicID, err = tx.GetPostureChecks(ctx, accountID); err != nil {
		return nil, fmt.Errorf("get posture checks: %w", err)
	}
	if rows.Routes, err = tx.GetRoutes(ctx, accountID); err != nil {
		return nil, fmt.Errorf("get routes: %w", err)
	}
	if rows.NetworkXIDToPublicID, err = tx.GetNetworkXIDToPublicIdMap(ctx, accountID); err != nil {
		return nil, fmt.Errorf("get network xid to public id map: %w", err)
	}
	if rows.AllowedUserIDs, rows.GroupIDToUserIDs, err = tx.GetAllowedUsers(ctx, accountID); err != nil {
		return nil, fmt.Errorf("get allowed users: %w", err)
	}
	if rows.DNSSettings, err = tx.GetDnsSettings(ctx, accountID); err != nil {
		return nil, fmt.Errorf("get dns settings: %w", err)
	}
	if rows.Domains, err = tx.GetDomains(ctx, accountID); err != nil {
		return nil, fmt.Errorf("get domains: %w", err)
	}
	if rows.ProxyTargetedDomainResourceIDs, err = tx.GetProxyTargetedDomainResourceIDs(ctx, accountID); err != nil {
		return nil, fmt.Errorf("get proxy targeted domain resources: %w", err)
	}

	if selectPeers == nil {
		if rows.Peers, _, err = tx.GetPeers(ctx, accountID); err != nil {
			return nil, fmt.Errorf("get peers: %w", err)
		}
		return rows, nil
	}

	if rows.Peers, err = tx.GetProxyPeers(ctx, accountID); err != nil {
		return nil, fmt.Errorf("get proxy peers: %w", err)
	}

	peerIDs, all, err := selectPeers(rows)
	if err != nil {
		return nil, err
	}
	switch {
	case all:
		if rows.Peers, _, err = tx.GetPeers(ctx, accountID); err != nil {
			return nil, fmt.Errorf("get peers: %w", err)
		}
	default:
		selected, err := tx.GetPeersByIDs(ctx, accountID, peerIDs)
		if err != nil {
			return nil, fmt.Errorf("get peers by id: %w", err)
		}
		rows.Peers = append(rows.Peers, selected...)
		if rows.PeerVersions, err = tx.GetPeerVersions(ctx, accountID); err != nil {
			return nil, fmt.Errorf("get peer versions: %w", err)
		}
	}
	return rows, nil
}

// newNetworkMapData assembles the network-map data from the rows of a load.
func newNetworkMapData(rows *AccountRows) *networkmap.NetworkMapData {
	resourcePolicies := buildResourcePolicies(
		rows.NetworkResources, rows.Policies, rows.ResourceToGroupIdx, rows.PolicyToDestinationResourceIdx, rows.PolicyToDestinationGroupIdx)

	return &networkmap.NetworkMapData{
		AccountSettings:                &rows.Settings,
		DNSSettings:                    &rows.DNSSettings,
		Network:                        &rows.Network,
		Peers:                          toMap(rows.Peers, func(p nmdata.Peer) string { return p.ID }),
		Groups:                         toMap(rows.Groups, func(g nmdata.Group) string { return g.ID }),
		Policies:                       toSliceOfPtrs(rows.Policies),
		ResourcePolicies:               resourcePolicies,
		Routes:                         toSliceOfPtrs(rows.Routes),
		Routers:                        rows.Routers,
		NameServerGroups:               toSliceOfPtrs(rows.NameServerGroups),
		NetworkResources:               toSliceOfPtrs(rows.NetworkResources),
		PostureChecks:                  toMap(rows.PostureChecks, func(pc nmdata.PostureChecks) string { return pc.ID }),
		AllowedUserIDs:                 rows.AllowedUserIDs,
		GroupIDToUserIDs:               rows.GroupIDToUserIDs,
		NetworkXIDToPublicID:           rows.NetworkXIDToPublicID, // TODO (dmitri) maybe we can switch to public ids everywhere?
		AppliedZoneCandidates:          rows.ZoneCandidates,
		Domains:                        TwinProxyDomains(rows.Domains),
		PostureCheckXIDToPublicID:      rows.PostureCheckXIDToPublicID,
		ProxyTargetedDomainResourceIDs: rows.ProxyTargetedDomainResourceIDs,
	}
}

func peerVersions(peers []nmdata.Peer) []string {
	seen := make(map[string]struct{})
	versions := make([]string, 0)
	for _, p := range peers {
		if _, ok := seen[p.Meta.WtVersion]; ok {
			continue
		}
		seen[p.Meta.WtVersion] = struct{}{}
		versions = append(versions, p.Meta.WtVersion)
	}
	return versions
}

func toMap[T any](all []T, id func(t T) string) map[string]*T {
	toret := make(map[string]*T, len(all))
	for _, t := range all {
		toret[id(t)] = &t
	}
	return toret
}

func toSliceOfPtrs[T any](all []T) []*T {
	toret := make([]*T, 0, len(all))
	for _, t := range all {
		toret = append(toret, &t)
	}
	return toret
}

// buildResourcePolicies maps every enabled network resource to the enabled
// policies targeting it, directly or through one of its groups, in policy
// order. Each policy resolves its targets through the indexes once.
func buildResourcePolicies(networkResources []nmdata.NetworkResource,
	policies []nmdata.Policy,
	resourceToGroupIdx map[string]map[string]any,
	policyToDestinationResourceIdx map[string]map[string]any,
	policyToDestinationGroupIdx map[string]map[string]any) map[string][]*nmdata.Policy {

	enabledResources := make(map[string]struct{}, len(networkResources))
	for _, resource := range networkResources {
		if resource.Enabled {
			enabledResources[resource.ID] = struct{}{}
		}
	}

	groupToResources := make(map[string][]string)
	for resourceID, groupIDs := range resourceToGroupIdx {
		for groupID := range groupIDs {
			groupToResources[groupID] = append(groupToResources[groupID], resourceID)
		}
	}

	resourcePolicies := make(map[string][]*nmdata.Policy)
	for i := range policies {
		if !policies[i].Enabled {
			continue
		}

		targets := make(map[string]struct{})
		for resourceID := range policyToDestinationResourceIdx[policies[i].ID] {
			targets[resourceID] = struct{}{}
		}
		for groupID := range policyToDestinationGroupIdx[policies[i].ID] {
			for _, resourceID := range groupToResources[groupID] {
				targets[resourceID] = struct{}{}
			}
		}

		var policy *nmdata.Policy
		for resourceID := range targets {
			if _, ok := enabledResources[resourceID]; !ok {
				continue
			}
			if policy == nil {
				p := policies[i]
				policy = &p
			}
			resourcePolicies[resourceID] = append(resourcePolicies[resourceID], policy)
		}
	}

	return resourcePolicies
}
