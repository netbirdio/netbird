package networkmap_pgsql

import (
	"context"

	"github.com/jackc/pgx/v5"
	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
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

func (pgc *PgStoreConn) GetPrivateServices(ctx context.Context, accountId string) ([]networkmapdb.Service, error) {
	rows, err := pgc.Conn.Query(ctx, GetServicesQuery, accountId)
	if err != nil {
		return nil, err
	}

	return pgx.CollectRows(rows, pgx.RowToStructByName[networkmapdb.Service])
}

func (pgc *PgStoreConn) GetProxyTargetedDomainResourceIDs(ctx context.Context, accountId string) (map[string]struct{}, error) {
	rows, err := pgc.Conn.Query(ctx, GetProxyTargetedDomainResourcesQuery, accountId)
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
