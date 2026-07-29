package networkmap_pgsql

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"

	"github.com/jackc/pgx/v5"
	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

const (
	GetNetworkRouterQuery = `
	select public_id, peer_groups, masquerade, metric, enabled
	from network_routers
	where account_id=$1
	`
)

func (pg *PgStore) GetNetworkRouters(ctx context.Context, accountId string) ([]nmdata.NetworkRouter, error) {
	rows, err := pg.pool.Query(ctx, GetNetworkRouterQuery, accountId)
	if err != nil {
		return nil, err
	}

	netrouters, err := pgx.CollectRows(rows, pgx.RowToStructByName[networkrouter])
	if err != nil {
		return nil, err
	}

	toret := make([]nmdata.NetworkRouter, 0, len(netrouters))
	for _, nrt := range netrouters {
		router := nmdata.NetworkRouter{}
		err := networkmapdb.FromSqlTypesToSharedTypes(
			reflect.ValueOf(&nrt).Elem(), reflect.ValueOf(&router).Elem())
		if err != nil {
			return nil, err
		}
		toret = append(toret, router)
	}
	return toret, nil
}

type networkrouter struct {
	PublicID   sql.NullString
	PeerGroups json.RawMessage
	Masquerade sql.NullBool
	Metric     sql.NullInt64
	Enabled    sql.NullBool
}
