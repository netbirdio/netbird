package networkmap_sqlite

import (
	"context"

	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
)

const (
	GetDomainsQuery = `
	select domain, target_cluster
	from domains
	where account_id=$1 and domain<>'' and target_cluster<>''
	`
)

func (sc *SqliteStoreConn) GetDomains(ctx context.Context, accountId string) ([]networkmapdb.Domain, error) {
	rows, err := sc.Conn.QueryContext(ctx, GetDomainsQuery, accountId)
	if err != nil {
		return nil, err
	}

	return networkmapdb.CollectRowsForSqlite[networkmapdb.Domain](rows)
}
