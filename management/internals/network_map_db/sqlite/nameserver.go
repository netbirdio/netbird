package networkmap_sqlite

import (
	"context"
	"database/sql"

	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

const (
	GetNameserversQuery = `
	select id, public_id, name, description, name_servers, groups, "primary", domains, enabled, search_domains_enabled
	from name_server_groups
	where account_id=$1
	`
)

func (sc *SqliteStoreConn) GetNameServerGroups(ctx context.Context, accountId string) ([]nmdata.NameServerGroup, error) {
	rows, err := sc.Conn.QueryContext(ctx, GetNameserversQuery, accountId)
	if err != nil {
		return nil, err
	}

	nsgroups, err := networkmapdb.CollectRowsForSqlite[nameserverGroup](rows)
	if err != nil {
		return nil, err
	}

	return networkmapdb.ConvertAllToSharedTypes[nameserverGroup, nmdata.NameServerGroup](nsgroups)
}

type nameserverGroup struct {
	ID                   string
	PublicID             sql.NullString
	Name                 sql.NullString
	Description          sql.NullString
	NameServers          []byte `nmap:"json"`
	Groups               []byte `nmap:"json"`
	Primary              sql.NullBool
	Domains              []byte `nmap:"json"`
	Enabled              sql.NullBool
	SearchDomainsEnabled sql.NullBool
}
