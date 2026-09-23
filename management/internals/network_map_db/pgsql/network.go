package networkmap_pgsql

import (
	"context"
	"reflect"

	"github.com/jackc/pgx/v5"
	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

const (
	GetNetworkQuery = `
	select network_identifier as identifier, network_net as net, network_net_v6 as net_v6, network_dns as dns, network_serial as serial
	from accounts
	where id=$1
	`
)

func (pgc *PgStoreConn) GetNetwork(ctx context.Context, accountId string) (nmdata.Network, error) {
	rows, err := pgc.Conn.Query(ctx, GetNetworkQuery, accountId)
	if err != nil {
		return nmdata.Network{}, err
	}

	n, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[networkmapdb.AccountNetwork])
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
