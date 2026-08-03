package networkmap_pgsql

import (
	"context"
	"database/sql"

	"github.com/jackc/pgx/v5"
)

const (
	GetServicesQuery = `
	select enabled, private, array (select json_array_elements_text(access_groups::json)) as access_groups, proxy_cluster, domain
	from services
	where account_id=$1
	`
)

func (pg *PgStore) GetPrivateServices(ctx context.Context, accountId string) ([]service, error) {
	c, err := pg.Pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	return GetPrivateServicesViaPgxConnection(ctx, c.Conn(), accountId)
}

func GetPrivateServicesViaPgxConnection(ctx context.Context, conn *pgx.Conn, accountId string) ([]service, error) {
	rows, err := conn.Query(ctx, GetServicesQuery, accountId)
	if err != nil {
		return nil, err
	}

	return pgx.CollectRows(rows, pgx.RowToStructByName[service])
}

type service struct {
	Enabled      sql.NullBool
	Private      sql.NullBool
	AccessGroups []string
	ProxyCluster sql.NullString
	Domain       sql.NullString
}
