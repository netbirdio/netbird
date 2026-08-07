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

	GetProxyTargetedDomainResourcesQuery = `
	select t.target_id
	from targets as t
	join services as s on s.id = t.service_id
	where s.account_id=$1 and s.enabled and not coalesce(s.terminated, false)
	and t.enabled and t.target_type='domain' and t.target_id is not null
	`
)

func (pg *PgStore) GetPrivateServices(ctx context.Context, accountId string) ([]Service, error) {
	c, err := pg.Pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	return GetPrivateServicesViaPgxConnection(ctx, c.Conn(), accountId)
}

func GetPrivateServicesViaPgxConnection(ctx context.Context, conn *pgx.Conn, accountId string) ([]Service, error) {
	rows, err := conn.Query(ctx, GetServicesQuery, accountId)
	if err != nil {
		return nil, err
	}

	return pgx.CollectRows(rows, pgx.RowToStructByName[Service])
}

func GetProxyTargetedDomainResourceIDsViaPgxConnection(ctx context.Context, conn *pgx.Conn, accountId string) (map[string]struct{}, error) {
	rows, err := conn.Query(ctx, GetProxyTargetedDomainResourcesQuery, accountId)
	if err != nil {
		return nil, err
	}

	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}

	toret := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		toret[id] = struct{}{}
	}
	return toret, nil
}

type Service struct {
	Enabled      sql.NullBool
	Private      sql.NullBool
	AccessGroups []string
	ProxyCluster sql.NullString
	Domain       sql.NullString
}
