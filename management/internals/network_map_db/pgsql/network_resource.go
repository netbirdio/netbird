package networkmap_pgsql

import (
	"context"

	"github.com/jackc/pgx/v5"
	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

const (
	GetNetworkResourcesQuery = `
	select id, network_id, account_id, public_id, name, description, type, domain, prefix, enabled
	from network_resources
	where account_id=$1
	`
)

func (pgc *PgStoreConn) GetNetworkResources(ctx context.Context, accountId string) ([]nmdata.NetworkResource, error) {
	rows, err := pgc.Conn.Query(ctx, GetNetworkResourcesQuery, accountId)
	if err != nil {
		return nil, err
	}

	netresorces, err := pgx.CollectRows(rows, pgx.RowToStructByName[networkmapdb.Networkresource])
	if err != nil {
		return nil, err
	}

	return networkmapdb.ConvertAllToSharedTypes[networkmapdb.Networkresource, nmdata.NetworkResource](netresorces)
}
