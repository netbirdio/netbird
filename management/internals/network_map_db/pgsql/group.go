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
	select id, name, public_id, resources,
	(
	  select array_agg(group_peers.peer_id)
      from group_peers
	  where group_peers.group_id = groups.id
	) as peers
	from groups where account_id=$1
	`
)

// we also return a resource-to-group index.
// an alternative is to add json indexes, query this directly. Not sure how expensive
// json indexes are. TODO (dmitri) verify and maybe change the implementation here.
func (pg *PgStore) GetGroups(ctx context.Context, accountId string) ([]nmdata.Group, map[string]map[string]any, error) {
	c, err := pg.Pool.Acquire(ctx)
	if err != nil {
		return nil, nil, err
	}
	return GetGroupsViaPgxConnection(ctx, c.Conn(), accountId)
}

func GetGroupsViaPgxConnection(ctx context.Context, con *pgx.Conn, accountId string) ([]nmdata.Group, map[string]map[string]any, error) {
	rows, err := con.Query(ctx, GetGroupsQuery, accountId)
	if err != nil {
		return nil, nil, err
	}

	groups, err := pgx.CollectRows(rows, pgx.RowToStructByName[group])
	toret := make([]nmdata.Group, 0, len(groups))
	resourceToGroupIdx := make(map[string]map[string]any)

	for _, g := range groups {
		dg := nmdata.Group{}
		err := networkmapdb.FromSqlTypesToSharedTypes(
			reflect.ValueOf(&g), reflect.ValueOf(&dg))
		if err != nil {
			return nil, nil, err
		}
		toret = append(toret, dg)
		for _, resource := range dg.Resources {
			if _, ok := resourceToGroupIdx[resource.ID]; !ok {
				resourceToGroupIdx[resource.ID] = make(map[string]any)
			}
			resourceToGroupIdx[resource.ID][g.Id] = struct{}{}
		}
	}

	return toret, resourceToGroupIdx, err
}

type group struct {
	Id        string `nmap:"skip"`
	Name      sql.NullString
	PublicID  sql.NullString
	Resources json.RawMessage
	Peers     []string
}
