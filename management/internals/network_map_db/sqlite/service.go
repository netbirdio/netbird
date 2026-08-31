package networkmap_sqlite

import (
	"context"
	"database/sql"
	"encoding/json"

	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
)

const (
	GetServicesQuery = `
	select enabled, private, access_groups, proxy_cluster, domain
	from services
	where account_id=?
	`

	GetProxyTargetedDomainResourcesQuery = `
	select t.target_id
	from targets as t
	join services as s on s.id = t.service_id
	where s.account_id=? and s.enabled and not coalesce(s.terminated, false)
	and t.enabled and t.target_type='domain' and t.target_id is not null
	`
)

func (sc *SqliteStoreConn) GetPrivateServices(ctx context.Context, accountId string) ([]networkmapdb.Service, error) {
	rows, err := sc.Conn.QueryContext(ctx, GetServicesQuery, accountId)
	if err != nil {
		return nil, err
	}

	services, err := CollectRowsForSqlite[service](rows)
	if err != nil {
		return nil, err
	}

	toret := make([]networkmapdb.Service, 0, len(services))
	for _, service := range services {
		acg := []string{}
		if service.AccessGroups != nil {
			if err := json.Unmarshal(service.AccessGroups, &acg); err != nil {
				return nil, err
			}
		}
		s := networkmapdb.Service{
			Enabled:      service.Enabled,
			Private:      service.Private,
			AccessGroups: acg,
			ProxyCluster: service.ProxyCluster,
			Domain:       service.Domain,
		}

		toret = append(toret, s)
	}
	return toret, nil
}

func (sc *SqliteStoreConn) GetProxyTargetedDomainResourceIDs(ctx context.Context, accountId string) (map[string]struct{}, error) {
	rows, err := sc.Conn.QueryContext(ctx, GetProxyTargetedDomainResourcesQuery, accountId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	toret := make(map[string]struct{})
	for rows.Next() {
		var id string
		err := rows.Scan(&id)
		if err != nil {
			return nil, err
		}
		toret[id] = struct{}{}
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return toret, nil
}

type service struct {
	Enabled      sql.NullBool
	Private      sql.NullBool
	AccessGroups []byte
	ProxyCluster sql.NullString
	Domain       sql.NullString
}
