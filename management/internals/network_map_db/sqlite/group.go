package networkmap_sqlite

import (
	"context"
	"database/sql"
	"reflect"

	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

const (
	GetGroupsQuery = `
	select groups.id, groups.name, groups.public_id, groups.resources, gp.peer_id
	from groups 
	left join group_peers gp on gp.group_id=groups.id and gp.account_id=?
	where groups.account_id=?
	`
)

// we also return a resource-to-group index.
// an alternative is to add json indexes, query this directly. Not sure how expensive
// json indexes are. TODO (dmitri) verify and maybe change the implementation here.
func (sc *SqliteStoreConn) GetGroups(ctx context.Context, accountId string) ([]nmdata.Group, map[string]map[string]any, error) {
	rows, err := sc.Conn.QueryContext(ctx, GetGroupsQuery, accountId, accountId)
	if err != nil {
		return nil, nil, err
	}

	groups, err := CollectRowsForSqlite[group](rows)

	toret := make([]nmdata.Group, 0, len(groups))
	resourceToGroupIdx := make(map[string]map[string]any)

	for _, g := range groups {
		if len(toret) > 0 && toret[len(toret)-1].ID == g.ID && g.PeerID.Valid {
			toret[len(toret)-1].Peers = append(toret[len(toret)-1].Peers, g.PeerID.String)
			continue
		}

		dg := nmdata.Group{}
		err := networkmapdb.FromSqlTypesToSharedTypes(
			reflect.ValueOf(&g), reflect.ValueOf(&dg))
		if err != nil {
			return nil, nil, err
		}

		if g.PeerID.Valid {
			dg.Peers = append(dg.Peers, g.PeerID.String)
		}
		toret = append(toret, dg)

		for _, resource := range dg.Resources {
			if _, ok := resourceToGroupIdx[resource.ID]; !ok {
				resourceToGroupIdx[resource.ID] = make(map[string]any)
			}
			resourceToGroupIdx[resource.ID][g.ID] = struct{}{}
		}
	}

	return toret, resourceToGroupIdx, err
}

type group struct {
	ID        string
	Name      sql.NullString
	PublicID  sql.NullString
	Resources []byte         `nmap:"json"`
	PeerID    sql.NullString `nmap:"skip"`
}
