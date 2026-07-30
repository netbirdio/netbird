package networkmap_pgsql

import (
	"context"
	"reflect"

	"github.com/jackc/pgx/v5"
	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

const (
	GetCustomZonesQuery = `
	select id, public_id, name, description, name_servers, groups, "primary", domains, enabled, search_domains_enabled
	from name_server_groups
	where account_id=$1
	`
)

func (pg *PgStore) GetCustomZones(ctx context.Context, accountId string) ([]nmdata.NameServerGroup, error) {
	rows, err := pg.pool.Query(ctx, GetNameserversQuery, accountId)
	if err != nil {
		return nil, err
	}

	nsgroups, err := pgx.CollectRows(rows, pgx.RowToStructByName[nameserverGroup])
	if err != nil {
		return nil, err
	}

	toret := make([]nmdata.NameServerGroup, 0, len(nsgroups))
	for _, nsg := range nsgroups {
		group := nmdata.NameServerGroup{}
		err := networkmapdb.FromSqlTypesToSharedTypes(
			reflect.ValueOf(&nsg), reflect.ValueOf(&group))
		if err != nil {
			return nil, err
		}
		toret = append(toret, group)
	}
	return toret, nil
}
