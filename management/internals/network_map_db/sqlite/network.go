package networkmap_sqlite

import (
	"context"
	"reflect"

	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

const (
	GetNetworkQuery = `
	select network_identifier as identifier, network_net as net, network_net_v6 as net_v6, network_dns as dns, network_serial as serial
	from accounts
	where id=?
	`
)

func (sc *SqliteStoreConn) GetNetwork(ctx context.Context, accountId string) (nmdata.Network, error) {
	rows, err := sc.Conn.QueryContext(ctx, GetNetworkQuery, accountId)
	if err != nil {
		return nmdata.Network{}, err
	}

	n, err := CollectOneRowForSqlite[networkmapdb.AccountNetwork](rows)
	if err != nil {
		return nmdata.Network{}, err
	}

	toret := nmdata.Network{}
	err = networkmapdb.FromSqlTypesToSharedTypes(
		reflect.ValueOf(&n), reflect.ValueOf(&toret))
	if err != nil {
		return nmdata.Network{}, err
	}

	return toret, nil
}
