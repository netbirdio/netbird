package networkmap_pgsql

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
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

func (pg *PgStore) GetNetwork(ctx context.Context, accountId string) (nmdata.Network, error) {
	c, err := pg.Pool.Acquire(ctx)
	if err != nil {
		return nmdata.Network{}, err
	}
	return GetNetworkViaConnection(ctx, c, accountId)
}

func GetNetworkViaConnection(ctx context.Context, con *pgxpool.Conn, accountId string) (nmdata.Network, error) {
	rows, err := con.Query(ctx, GetNetworkQuery, accountId)
	if err != nil {
		return nmdata.Network{}, err
	}

	n, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[network])
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

type network struct {
	Identifier sql.NullString
	Net        json.RawMessage
	NetV6      json.RawMessage
	Dns        sql.NullString
	Serial     sql.NullInt64
}
