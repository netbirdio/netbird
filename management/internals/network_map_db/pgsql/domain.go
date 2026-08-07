package networkmap_pgsql

import (
	"context"
	"database/sql"

	"github.com/jackc/pgx/v5"
)

const (
	GetDomainsQuery = `
	select domain, target_cluster
	from domains
	where account_id=$1 and domain<>'' and target_cluster<>''
	`
)

func (pg *PgStore) GetDomains(ctx context.Context, accountId string) ([]Domain, error) {
	c, err := pg.Pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	return GetDomainsViaPgxConnection(ctx, c.Conn(), accountId)
}

func GetDomainsViaPgxConnection(ctx context.Context, conn *pgx.Conn, accountId string) ([]Domain, error) {
	rows, err := conn.Query(ctx, GetDomainsQuery, accountId)
	if err != nil {
		return nil, err
	}

	return pgx.CollectRows(rows, pgx.RowToStructByName[Domain])
}

type Domain struct {
	Domain        sql.NullString
	TargetCluster sql.NullString
}
