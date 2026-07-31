package networkmap_pgsql

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/jackc/pgx/v5"
)

const (
	GetNetworkRouterQuery = `
	select public_id, peer, peer_groups, network_id, masquerade, metric, enabled,
	from network_routers
	where account_id=$1
	`
)

// func (pg *PgStore) GetNetworkRouters(ctx context.Context, accountId string) ([]nmdata.NetworkRouter, error) {
// 	c, err := pg.Pool.Acquire(ctx)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return GetNetworkRoutersViaPgxConnection(ctx, c.Conn(), accountId)
// }

func GetNetworkRoutersViaPgxConnection(ctx context.Context, con *pgx.Conn, accountId string) ([]networkrouter, error) {
	rows, err := con.Query(ctx, GetNetworkRouterQuery, accountId)
	if err != nil {
		return nil, err
	}

	return pgx.CollectRows(rows, pgx.RowToStructByName[networkrouter])
	// if err != nil {
	// 	return nil, err
	// }
	//
	// toret := make([]nmdata.NetworkRouter, 0, len(netrouters))
	// for _, nrt := range netrouters {
	// 	router := nmdata.NetworkRouter{}
	// 	err := networkmapdb.FromSqlTypesToSharedTypes(
	// 		reflect.ValueOf(&nrt), reflect.ValueOf(&router))
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	toret = append(toret, router)
	// }
	// return toret, nil
}

type networkrouter struct {
	PublicID   sql.NullString
	NetworkID  sql.NullString `nmap:"skip"`
	Peer       sql.NullString `nmap:"skip"`
	PeerGroups json.RawMessage
	Masquerade sql.NullBool
	Metric     sql.NullInt64
	Enabled    sql.NullBool
}
