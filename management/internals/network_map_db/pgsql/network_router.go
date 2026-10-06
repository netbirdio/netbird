package networkmap_pgsql

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/jackc/pgx/v5"
	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

const (
	GetNetworkRouterQuery = `
	select public_id, peer, network_id, masquerade, metric, enabled, peer_groups,
	(
	  select array_agg(group_peers.peer_id)
	  from group_peers
	  where group_peers.account_id=$1 and group_peers.group_id in (select json_array_elements_text(peer_groups::json))
	) as peers_via_groups
	from network_routers
	where account_id=$1
	`
)

func (pgc *PgStoreConn) GetNetworkRouters(ctx context.Context, accountId string) (map[string]map[string]*nmdata.NetworkRouter, error) {
	rows, err := pgc.Conn.Query(ctx, GetNetworkRouterQuery, accountId)
	if err != nil {
		return nil, err
	}

	routers, err := pgx.CollectRows(rows, pgx.RowToStructByName[networkrouter])
	if err != nil {
		return nil, err
	}

	toret := make(map[string]map[string]*nmdata.NetworkRouter)
	for _, router := range routers {
		if !router.Enabled.Bool {
			continue
		}

		networkId := router.NetworkID.String
		if networkId == "" {
			return nil, fmt.Errorf("router with public_id %s doesn't have network_id set", router.PublicID.String)
		}

		nmdatarouter := nmdata.NetworkRouter{}
		err := networkmapdb.FromSqlTypesToSharedTypes(reflect.ValueOf(&router), reflect.ValueOf(&nmdatarouter))
		if err != nil {
			return nil, err
		}

		if toret[networkId] == nil {
			toret[networkId] = make(map[string]*nmdata.NetworkRouter)
		}
		if router.Peer.String != "" {
			toret[networkId][router.Peer.String] = &nmdatarouter
			continue
		}
		for _, peerId := range router.PeersViaGroups {
			toret[networkId][peerId] = &nmdatarouter
		}
	}

	return toret, nil
}

type networkrouter struct {
	PublicID       sql.NullString
	NetworkID      sql.NullString `nmap:"skip"`
	Peer           sql.NullString `nmap:"skip"`
	PeerGroups     json.RawMessage
	PeersViaGroups []string `nmap:"skip"`
	Masquerade     sql.NullBool
	Metric         sql.NullInt64
	Enabled        sql.NullBool
}
