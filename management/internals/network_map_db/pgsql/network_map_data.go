package networkmap_pgsql

import (
	"context"
	"fmt"
	"reflect"

	"github.com/jackc/pgx/v5"
	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
	"github.com/netbirdio/netbird/shared/management/networkmap"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

func (pg *PgStore) GetNetworkMapData(ctx context.Context, accountId string) (*networkmap.NetworkMapData, error) {
	tx, err := pg.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}

	// acctSettings, err := GetAccountSettingsViaPgxConnection(ctx, tx.Conn(), accountId)
	// if err != nil {
	// 	return rollbackAndReturnError(ctx, tx, err)
	// }
	// dnsZones, err := GetAccountZonesViaPgxConnection(ctx, tx.Conn(), accountId)
	// if err != nil {
	// 	return rollbackAndReturnError(ctx, tx, err)
	// }
	groups, err := GetGroupsViaPgxConnection(ctx, tx.Conn(), accountId)
	if err != nil {
		return rollbackAndReturnError(ctx, tx, err)
	}
	nsGroups, err := GetNameServerGroupsViaPgxConnection(ctx, tx.Conn(), accountId)
	if err != nil {
		return rollbackAndReturnError(ctx, tx, err)
	}
	networkResources, err := GetNetworkResourcesViaPgxConnection(ctx, tx.Conn(), accountId)
	if err != nil {
		return rollbackAndReturnError(ctx, tx, err)
	}
	// TODO (dmitri) this needs cleaning up -- returns an internal struct
	routers, err := GetNetworkRoutersViaPgxConnection(ctx, tx.Conn(), accountId)
	if err != nil {
		return rollbackAndReturnError(ctx, tx, err)
	}
	network, err := GetNetworkViaPgxConnection(ctx, tx.Conn(), accountId)
	if err != nil {
		return rollbackAndReturnError(ctx, tx, err)
	}
	peers, err := GetPeersViaPgxConnection(ctx, tx.Conn(), accountId)
	if err != nil {
		return rollbackAndReturnError(ctx, tx, err)
	}
	policies, err := GetPoliciesViaPgxConnection(ctx, tx.Conn(), accountId)
	if err != nil {
		return rollbackAndReturnError(ctx, tx, err)
	}
	postureChecks, err := GetPostureChecksViaPgxConnection(ctx, tx.Conn(), accountId)
	if err != nil {
		return rollbackAndReturnError(ctx, tx, err)
	}
	routes, err := GetRoutesViaPgxConnection(ctx, tx.Conn(), accountId)
	if err != nil {
		return rollbackAndReturnError(ctx, tx, err)
	}
	networkXIDToPublicID, err := GetNetworkXIDToPublicIdMapViaPgxConnection(ctx, tx.Conn(), accountId)
	if err != nil {
		return rollbackAndReturnError(ctx, tx, err)
	}

	err = tx.Commit(ctx)
	if err != nil {
		// TODO log and ignore?
	}

	toret := networkmap.NetworkMapData{
		Network:              &network,
		Peers:                toMap(peers, func(p nmdata.Peer) string { return p.ID }),
		Groups:               toMap(groups, func(g nmdata.Group) string { return g.PublicID }),
		Policies:             toSliceOfPtrs(policies),
		Routes:               toSliceOfPtrs(routes),
		NameServerGroups:     toSliceOfPtrs(nsGroups),
		NetworkResources:     toSliceOfPtrs(networkResources),
		PostureChecks:        toMap(postureChecks, func(pc nmdata.PostureChecks) string { return pc.ID }),
		NetworkXIDToPublicID: networkXIDToPublicID, // TODO (dmitri-d) do we still need it now?
	}

	networktoRouters := make(map[string]map[string]*nmdata.NetworkRouter)
	for _, router := range routers {
		if !router.Enabled.Bool {
			continue
		}

		if router.NetworkID.String == "" {
			return nil, fmt.Errorf("router with public_id %s doesn't have network_id set", router.PublicID.String)
		}
		networkPublicId := networkXIDToPublicID[router.NetworkID.String]
		if networkPublicId == "" {
			return nil, fmt.Errorf("network with id %s has no public_id", router.NetworkID.String)
		}

		nmdatarouter := nmdata.NetworkRouter{}
		err := networkmapdb.FromSqlTypesToSharedTypes(reflect.ValueOf(&router), reflect.ValueOf(&nmdatarouter))
		if err != nil {
			return nil, err
		}

		if networktoRouters[networkPublicId] == nil {
			networktoRouters[networkPublicId] = make(map[string]*nmdata.NetworkRouter)
		}
		if router.Peer.String != "" {
			networktoRouters[networkPublicId][router.Peer.String] = &nmdatarouter
		}
		for _, peerGroup := range nmdatarouter.PeerGroups {
			g := toret.Groups[peerGroup]
			if g != nil {
				for _, peerID := range g.Peers {
					networktoRouters[networkPublicId][peerID] = &nmdatarouter
				}
			}
		}
	}
	toret.Routers = networktoRouters

	return &toret, nil
}

func rollbackAndReturnError(ctx context.Context, tx pgx.Tx, err error) (*networkmap.NetworkMapData, error) {
	if errr := tx.Rollback(ctx); errr != nil {
		// TODO log and ignore?
	}
	return nil, err
}

func toMap[T any](all []T, id func(t T) string) map[string]*T {
	toret := make(map[string]*T, len(all))
	for _, t := range all {
		toret[id(t)] = &t
	}
	return toret
}

func toSliceOfPtrs[T any](all []T) []*T {
	toret := make([]*T, len(all))
	for _, t := range all {
		toret = append(toret, &t)
	}
	return toret
}
