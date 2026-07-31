package networkmap_pgsql

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"

	"github.com/jackc/pgx/v5"
	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

const (
	GetNetworkResourcesQuery = `
	select id, network_id, account_id, public_id, name, description, type, domain, prefix, enabled
	from network_resources
	where account_id=$1
	`
)

func (pg *PgStore) GetNetworkResources(ctx context.Context, accountId string) ([]nmdata.NetworkResource, error) {
	c, err := pg.Pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	return GetNetworkResourcesViaPgxConnection(ctx, c.Conn(), accountId)
}

func GetNetworkResourcesViaPgxConnection(ctx context.Context, con *pgx.Conn, accountId string) ([]nmdata.NetworkResource, error) {
	rows, err := con.Query(ctx, GetNetworkResourcesQuery, accountId)
	if err != nil {
		return nil, err
	}

	netresorces, err := pgx.CollectRows(rows, pgx.RowToStructByName[networkresource])
	if err != nil {
		return nil, err
	}

	toret := make([]nmdata.NetworkResource, 0, len(netresorces))
	for _, nres := range netresorces {
		resource := nmdata.NetworkResource{}
		err := networkmapdb.FromSqlTypesToSharedTypes(
			reflect.ValueOf(&nres), reflect.ValueOf(&resource))
		if err != nil {
			return nil, err
		}
		toret = append(toret, resource)
	}
	return toret, nil
}

type networkresource struct {
	ID          string
	NetworkID   sql.NullString
	AccountID   sql.NullString
	PublicID    sql.NullString
	Name        sql.NullString
	Description sql.NullString
	Type        sql.NullString
	Domain      sql.NullString
	Prefix      json.RawMessage
	Enabled     sql.NullBool
}
