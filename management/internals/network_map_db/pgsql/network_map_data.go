package networkmap_pgsql

import (
	"context"

	"github.com/jackc/pgx/v5"
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
	groups, netResourceToGroups, err := GetGroupsViaPgxConnection(ctx, tx.Conn(), accountId)
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
		Routers:              routers,
		NameServerGroups:     toSliceOfPtrs(nsGroups),
		NetworkResources:     toSliceOfPtrs(networkResources),
		PostureChecks:        toMap(postureChecks, func(pc nmdata.PostureChecks) string { return pc.ID }),
		NetworkXIDToPublicID: networkXIDToPublicID, // TODO (dmitri) maybe we can switch to public ids everywhere?
	}

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
