package networkmap_sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"

	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

const (
	// Outer join: a groupless router must survive.
	GetNetworkRouterQuery = `
	select public_id, peer, network_id, masquerade, metric, enabled, peer_groups, group_peers.peer_id
	from network_routers
	left join json_each(network_routers.peer_groups) on true
	left join group_peers on group_peers.account_id=? and group_peers.group_id=json_each.value
	where network_routers.account_id=?
	`
)

func (sc *SqliteStoreConn) GetNetworkRouters(ctx context.Context, accountId string) (map[string]map[string]*nmdata.NetworkRouter, error) {
	rows, err := sc.Conn.QueryContext(ctx, GetNetworkRouterQuery, accountId, accountId)
	if err != nil {
		return nil, err
	}

	routers, err := CollectRowsForSqlite[networkrouter](rows)
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
		if router.PeerViaGroups.String != "" {
			toret[networkId][router.PeerViaGroups.String] = &nmdatarouter
		}
	}

	return toret, nil
}

type networkrouter struct {
	PublicID      sql.NullString
	Peer          sql.NullString `nmap:"skip"`
	NetworkID     sql.NullString `nmap:"skip"`
	Masquerade    sql.NullBool
	Metric        sql.NullInt64
	Enabled       sql.NullBool
	PeerGroups    []byte         `nmap:"json"`
	PeerViaGroups sql.NullString `nmap:"skip"`
}
