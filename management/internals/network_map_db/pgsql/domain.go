package networkmap_pgsql

import (
	"context"

	"github.com/jackc/pgx/v5"
	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
)

const (
	GetDomainsQuery = `
	select domain, target_cluster
	from domains
	where account_id=$1 and domain<>'' and target_cluster<>''
	`
)

func (pgc *PgStoreConn) GetDomains(ctx context.Context, accountId string) ([]networkmapdb.Domain, error) {
	rows, err := pgc.Conn.Query(ctx, GetDomainsQuery, accountId)
	if err != nil {
		return nil, err
	}

	return pgx.CollectRows(rows, pgx.RowToStructByName[networkmapdb.Domain])
}
