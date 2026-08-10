package networkmap_pgsql

import (
	"context"

	"github.com/jackc/pgx/v5"
	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

const (
	GetNameserversQuery = `
	select id, public_id, name, description, name_servers, groups, "primary", domains, enabled, search_domains_enabled
	from name_server_groups
	where account_id=$1
	`
)

func (pgc *PgStoreConn) GetNameServerGroups(ctx context.Context, accountId string) ([]nmdata.NameServerGroup, error) {
	rows, err := pgc.Conn.Query(ctx, GetNameserversQuery, accountId)
	if err != nil {
		return nil, err
	}

	nsgroups, err := pgx.CollectRows(rows, pgx.RowToStructByName[networkmapdb.NameserverGroup])
	if err != nil {
		return nil, err
	}

	return networkmapdb.ConvertAllToSharedTypes[networkmapdb.NameserverGroup, nmdata.NameServerGroup](nsgroups)
}
