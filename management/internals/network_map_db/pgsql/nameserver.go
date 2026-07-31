package networkmap_pgsql

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
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

func (pg *PgStore) GetNameServerGroups(ctx context.Context, accountId string) ([]nmdata.NameServerGroup, error) {
	c, err := pg.Pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	return GetNameServerGroupsViaConnection(ctx, c, accountId)
}

func GetNameServerGroupsViaConnection(ctx context.Context, con *pgxpool.Conn, accountId string) ([]nmdata.NameServerGroup, error) {
	rows, err := con.Query(ctx, GetNameserversQuery, accountId)
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

type nameserverGroup struct {
	ID                   string
	PublicID             sql.NullString
	Name                 sql.NullString
	Description          sql.NullString
	NameServers          json.RawMessage
	Groups               json.RawMessage
	Primary              sql.NullBool
	Domains              json.RawMessage
	Enabled              sql.NullBool
	SearchDomainsEnabled sql.NullBool
}
