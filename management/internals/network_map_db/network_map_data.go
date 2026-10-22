package networkmapdb

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"

	"github.com/netbirdio/netbird/shared/management/networkmap"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

// GetNetworkMapData reads the network map data of the account. With a Replica
// configured it reads from the replica once that has replicated the account's
// current network serial, and from Store when it does not catch up within
// ReplicaWait or the replica read fails.
func (s *NetworkMapDBStoreImpl) GetNetworkMapData(ctx context.Context, accountId string) (*networkmap.NetworkMapData, error) {
	toret, err := s.readNetworkMapData(ctx, accountId)
	if err != nil {
		return nil, err
	}

	extraSettings, err := s.ExtraSettingsManager.GetExtraSettings(ctx, accountId)
	if err != nil {
		return nil, err
	}

	toret.ValidatedPeers, err = s.IntegratedPeerValidator.GetValidatedPeers(ctx, accountId, maps.Values(toret.Groups), maps.Values(toret.Peers), extraSettings)
	if err != nil {
		return nil, err
	}

	return toret, nil
}

func (s *NetworkMapDBStoreImpl) readNetworkMapData(ctx context.Context, accountId string) (*networkmap.NetworkMapData, error) {
	if s.Replica != nil {
		toret, err := s.readFromReplica(ctx, accountId)
		if err == nil {
			return toret, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		log.WithContext(ctx).Warnf("reading network map data of account %s from primary: %v", accountId, err)
	}

	tx, network, err := beginRead(ctx, s.Store, accountId)
	if err != nil {
		return nil, err
	}
	return readFromTx(ctx, tx, accountId, network)
}

func (s *NetworkMapDBStoreImpl) readFromReplica(ctx context.Context, accountId string) (*networkmap.NetworkMapData, error) {
	tx, network, err := s.beginOnReplica(ctx, accountId)
	if err != nil {
		return nil, err
	}
	return readFromTx(ctx, tx, accountId, network)
}

// beginOnReplica opens a read transaction on the replica whose snapshot holds at
// least the account's network serial on the primary at the time of the call.
func (s *NetworkMapDBStoreImpl) beginOnReplica(ctx context.Context, accountId string) (NetworkMapDBStoreConn, nmdata.Network, error) {
	primaryTx, primaryNetwork, err := beginRead(ctx, s.Store, accountId)
	if err != nil {
		return nil, nmdata.Network{}, fmt.Errorf("read primary network serial: %w", err)
	}
	rollbackTx(ctx, primaryTx)

	timeout := time.NewTimer(s.ReplicaWait)
	defer timeout.Stop()

	for {
		tx, network, err := beginRead(ctx, s.Replica, accountId)
		if err != nil {
			return nil, nmdata.Network{}, err
		}
		if network.Serial >= primaryNetwork.Serial {
			return tx, network, nil
		}
		rollbackTx(ctx, tx)

		select {
		case <-ctx.Done():
			return nil, nmdata.Network{}, ctx.Err()
		case <-timeout.C:
			return nil, nmdata.Network{}, fmt.Errorf("replica at network serial %d after %s, primary at %d", network.Serial, s.ReplicaWait, primaryNetwork.Serial)
		case <-time.After(replicaPollInterval):
		}
	}
}

// beginRead opens a read transaction and reads the account's network as its
// first statement, so the network serial belongs to the transaction's snapshot.
func beginRead(ctx context.Context, store NetworkMapDBStore, accountId string) (NetworkMapDBStoreConn, nmdata.Network, error) {
	tx, err := store.BeginTx(ctx)
	if err != nil {
		return nil, nmdata.Network{}, err
	}

	network, err := tx.GetNetwork(ctx, accountId)
	if err != nil {
		rollbackTx(ctx, tx)
		return nil, nmdata.Network{}, fmt.Errorf("get network: %w", err)
	}

	return tx, network, nil
}

// readFromTx reads the remaining network map data in tx and ends it.
func readFromTx(ctx context.Context, tx NetworkMapDBStoreConn, accountId string, network nmdata.Network) (*networkmap.NetworkMapData, error) {
	acctSettings, err := tx.GetAccountSettings(ctx, accountId)
	if err != nil {
		return rollbackAndReturnError(ctx, tx, fmt.Errorf("failed to get account settings: %w", err))
	}
	dnsZones, err := tx.GetAppliedZoneCandidates(ctx, accountId)
	if err != nil {
		return rollbackAndReturnError(ctx, tx, fmt.Errorf("failed to get applied zone candidates: %w", err))
	}
	groups, resourceToGroupIdx, err := tx.GetGroups(ctx, accountId)
	if err != nil {
		return rollbackAndReturnError(ctx, tx, fmt.Errorf("failed to get groups: %w", err))
	}
	nsGroups, err := tx.GetNameServerGroups(ctx, accountId)
	if err != nil {
		return rollbackAndReturnError(ctx, tx, fmt.Errorf("failed to get nameserver groups: %w", err))
	}
	networkResources, err := tx.GetNetworkResources(ctx, accountId)
	if err != nil {
		return rollbackAndReturnError(ctx, tx, fmt.Errorf("failed to get network resources: %w", err))
	}
	routers, err := tx.GetNetworkRouters(ctx, accountId)
	if err != nil {
		return rollbackAndReturnError(ctx, tx, fmt.Errorf("failed to get network routers: %w", err))
	}
	peers, _, err := tx.GetPeers(ctx, accountId)
	if err != nil {
		return rollbackAndReturnError(ctx, tx, fmt.Errorf("failed to get peers: %w", err))
	}
	policies, policyToDestinationResourceIdx, policyToDestinationGroupIdx, err := tx.GetPolicies(ctx, accountId)
	if err != nil {
		return rollbackAndReturnError(ctx, tx, fmt.Errorf("failed to get policies: %w", err))
	}
	postureChecks, postureCheckXIDToPublicID, err := tx.GetPostureChecks(ctx, accountId)
	if err != nil {
		return rollbackAndReturnError(ctx, tx, fmt.Errorf("failed to get posture checks: %w", err))
	}
	routes, err := tx.GetRoutes(ctx, accountId)
	if err != nil {
		return rollbackAndReturnError(ctx, tx, fmt.Errorf("failed to get routes: %w", err))
	}
	networkXIDToPublicID, err := tx.GetNetworkXIDToPublicIdMap(ctx, accountId)
	if err != nil {
		return rollbackAndReturnError(ctx, tx, fmt.Errorf("failed to get network xid to public id map: %w", err))
	}
	allowedUserIds, groupsToUserIds, err := tx.GetAllowedUsers(ctx, accountId)
	if err != nil {
		return rollbackAndReturnError(ctx, tx, fmt.Errorf("failed to get allowed users: %w", err))
	}
	dnsSettings, err := tx.GetDnsSettings(ctx, accountId)
	if err != nil {
		return rollbackAndReturnError(ctx, tx, fmt.Errorf("failed to get dns settings: %w", err))
	}
	domains, err := tx.GetDomains(ctx, accountId)
	if err != nil {
		return rollbackAndReturnError(ctx, tx, err)
	}
	proxyTargetedDomainResourceIDs, err := tx.GetProxyTargetedDomainResourceIDs(ctx, accountId)
	if err != nil {
		return rollbackAndReturnError(ctx, tx, fmt.Errorf("failed to get proxy targeted domain resources: %w", err))
	}

	if err = tx.CommitTx(ctx); err != nil {
		log.WithContext(ctx).Warnf("failed to commit network map read transaction: %v", err)
	}

	resourcePolicies := buildResourcePolicies(
		networkResources, policies, resourceToGroupIdx, policyToDestinationResourceIdx, policyToDestinationGroupIdx)

	toret := networkmap.NetworkMapData{
		AccountSettings:                &acctSettings,
		DNSSettings:                    &dnsSettings,
		Network:                        &network,
		Peers:                          toMap(peers, func(p nmdata.Peer) string { return p.ID }),
		Groups:                         toMap(groups, func(g nmdata.Group) string { return g.ID }),
		Policies:                       toSliceOfPtrs(policies),
		ResourcePolicies:               resourcePolicies,
		Routes:                         toSliceOfPtrs(routes),
		Routers:                        routers,
		NameServerGroups:               toSliceOfPtrs(nsGroups),
		NetworkResources:               toSliceOfPtrs(networkResources),
		PostureChecks:                  toMap(postureChecks, func(pc nmdata.PostureChecks) string { return pc.ID }),
		AllowedUserIDs:                 allowedUserIds,
		GroupIDToUserIDs:               groupsToUserIds,
		NetworkXIDToPublicID:           networkXIDToPublicID, // TODO (dmitri) maybe we can switch to public ids everywhere?
		AppliedZoneCandidates:          dnsZones,
		Domains:                        TwinProxyDomains(domains),
		PostureCheckXIDToPublicID:      postureCheckXIDToPublicID,
		ProxyTargetedDomainResourceIDs: proxyTargetedDomainResourceIDs,
	}

	return &toret, nil
}

func rollbackAndReturnError(ctx context.Context, tx NetworkMapDBStoreConn, err error) (*networkmap.NetworkMapData, error) {
	rollbackTx(ctx, tx)
	return nil, err
}

func rollbackTx(ctx context.Context, tx NetworkMapDBStoreConn) {
	if err := tx.RollbackTx(ctx); err != nil {
		log.WithContext(ctx).Warnf("failed to rollback network map read transaction: %v", err)
	}
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

func buildResourcePolicies(networkResources []nmdata.NetworkResource,
	policies []nmdata.Policy,
	resourceToGroupIdx map[string]map[string]any,
	policyToDestinationResourceIdx map[string]map[string]any,
	policyToDestinationGroupIdx map[string]map[string]any) map[string][]*nmdata.Policy {

	resourcePolicies := make(map[string][]*nmdata.Policy)
	for _, resource := range networkResources {
		if !resource.Enabled {
			continue
		}
		networkResourceGroups := resourceToGroupIdx[resource.ID]
		for _, policy := range policies {
			if !policy.Enabled {
				continue
			}
			if _, ok := policyToDestinationResourceIdx[policy.ID][resource.ID]; ok {
				resourcePolicies[resource.ID] = append(resourcePolicies[resource.ID], &policy) // TODO (dmitri) maybe use public id?
				continue
			}
			if groupIds, ok := policyToDestinationGroupIdx[policy.ID]; ok {
				for networkResourceGroup := range networkResourceGroups {
					if _, ok := groupIds[networkResourceGroup]; ok {
						resourcePolicies[resource.ID] = append(resourcePolicies[resource.ID], &policy)
						break
					}
				}
			}
		}
	}

	return resourcePolicies
}
