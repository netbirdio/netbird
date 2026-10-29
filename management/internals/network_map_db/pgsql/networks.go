package networkmap_pgsql

import (
	"context"

	"github.com/jackc/pgx/v5"
	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
)

const (
	GetNetworksQuery = `
	select id, public_id
	from networks where account_id=$1
	`
)

func (pgc *PgStoreConn) GetNetworkXIDToPublicIdMap(ctx context.Context, accountId string) (map[string]string, error) {
	rows, err := pgc.Conn.Query(ctx, GetNetworksQuery, accountId)
	if err != nil {
		return nil, err
	}

	networks, err := pgx.CollectRows(rows, pgx.RowToStructByName[networkmapdb.Network])
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
