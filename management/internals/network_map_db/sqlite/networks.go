package networkmap_sqlite

import (
	"context"

	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
)

const (
	GetNetworksQuery = `
	select id, public_id
	from networks where account_id=?
	`
)

func (sc *SqliteStoreConn) GetNetworkXIDToPublicIdMap(ctx context.Context, accountId string) (map[string]string, error) {
	rows, err := sc.Conn.QueryContext(ctx, GetNetworksQuery, accountId)
	if err != nil {
		return nil, err
	}

	networks, err := CollectRowsForSqlite[networkmapdb.Network](rows)
	if err != nil {
		return nil, err
	}

	toret := make(map[string]string)
	for _, n := range networks {
		if n.PublicID.Valid {
			toret[n.ID] = n.PublicID.String
		}
	}

	return toret, nil
}
