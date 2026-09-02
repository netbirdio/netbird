package networkmap_sqlite

import (
	"context"

	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

const (
	GetNetworkResourcesQuery = `
	select id, network_id, account_id, public_id, name, description, type, domain, prefix, enabled
	from network_resources
	where account_id=?
	`
)

func (sc *SqliteStoreConn) GetNetworkResources(ctx context.Context, accountId string) ([]nmdata.NetworkResource, error) {
	rows, err := sc.Conn.QueryContext(ctx, GetNetworkResourcesQuery, accountId)
	if err != nil {
		return nil, err
	}

	netresorces, err := CollectRowsForSqlite[networkmapdb.Networkresource](rows)
	if err != nil {
		return nil, err
	}

	return networkmapdb.ConvertAllToSharedTypes[networkmapdb.Networkresource, nmdata.NetworkResource](netresorces)
}
