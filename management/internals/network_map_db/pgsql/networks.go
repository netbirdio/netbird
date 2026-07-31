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

func (pg *PgStore) GetNetworks(ctx context.Context, accountId string) ([]network, error) {
	c, err := pg.Pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	return GetNetworksViaPgxConnection(ctx, c.Conn(), accountId)
}

func GetNetworksViaPgxConnection(ctx context.Context, con *pgx.Conn, accountId string) ([]network, error) {
	rows, err := con.Query(ctx, GetGroupsQuery, accountId)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByName[network])
}

func GetNetworkXIDToPublicIdMapViaPgxConnection(ctx context.Context, con *pgx.Conn, accountId string) (map[string]string, error) {
	networks, err := GetNetworksViaPgxConnection(ctx, con, accountId)
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
