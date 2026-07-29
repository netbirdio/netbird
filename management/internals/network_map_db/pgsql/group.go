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
	GetGroupsQuery = `
	select name, public_id, resources,
	(
	  select array_agg(group_peers.peer_id)
      from group_peers
	  where group_peers.group_id = groups.id
	) as peers
	from groups where account_id=$1
	`
)

func (pg *PgStore) GetGroups(ctx context.Context, accountId string) ([]nmdata.Group, error) {
	rows, err := pg.pool.Query(ctx, GetGroupsQuery, accountId)
	if err != nil {
		return nil, err
	}

	groups, err := pgx.CollectRows(rows, pgx.RowToStructByName[group])
	toret := make([]nmdata.Group, 0, len(groups))
	for _, g := range groups {
		dg := nmdata.Group{}
		err := networkmapdb.FromSqlTypesToSharedTypes(
			reflect.ValueOf(&g).Elem(), reflect.ValueOf(&dg).Elem())
		if err != nil {
			return nil, err
		}
		toret = append(toret, dg)
	}

	return toret, err
}

type group struct {
	Name      sql.NullString
	PublicID  sql.NullString
	Resources json.RawMessage
	Peers     []string
}
