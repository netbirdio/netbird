package networkmap_pgsql

import (
	"context"
	"database/sql"

	"github.com/jackc/pgx/v5"
)

const (
	GetNetworksQuery = `
	select id, public_id
	from networks where account_id=$1
	`
)

func (pgc *PgStoreConn) GetNetworks(ctx context.Context, accountId string) ([]network, error) {
	rows, err := pgc.Conn.Query(ctx, GetNetworksQuery, accountId)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByName[network])
}

func (pgc *PgStoreConn) GetNetworkXIDToPublicIdMap(ctx context.Context, accountId string) (map[string]string, error) {
	networks, err := pgc.GetNetworks(ctx, accountId)
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

type network struct {
	ID       string
	PublicID sql.NullString
}
