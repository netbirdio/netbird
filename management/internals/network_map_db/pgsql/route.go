package networkmap_pgsql

import (
	"context"

	"github.com/jackc/pgx/v5"
	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

const (
	GetRoutesQuery = `
	select id, account_id, public_id, network, domains, keep_route, net_id, description,
	peer, peer as peer_id, peer_groups, network_type, masquerade, metric, enabled, 
	groups, access_control_groups, skip_auto_apply
	from routes
	where account_id=$1
	`
)

func (pgc *PgStoreConn) GetRoutes(ctx context.Context, accountId string) ([]nmdata.Route, error) {
	rows, err := pgc.Conn.Query(ctx, GetRoutesQuery, accountId)
	if err != nil {
		return nil, err
	}

	routes, err := pgx.CollectRows(rows, pgx.RowToStructByName[networkmapdb.Route])
	if err != nil {
		return nil, err
	}

	return networkmapdb.ConvertAllToSharedTypes[networkmapdb.Route, nmdata.Route](routes)
}
