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
	GetRoutesQuery = `
	select id, account_id, public_id, network, domains, keep_route, net_id, description,
	peer, peer as peer_id, peer_groups, network_type, masquerade, metric, enabled, 
	groups, access_control_groups, skip_auto_apply
	from routes
	where account_id=$1
	`
)

func (pg *PgStore) GetRoutes(ctx context.Context, accountId string) ([]nmdata.Route, error) {
	c, err := pg.Pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	return GetRoutesViaConnection(ctx, c, accountId)
}

func GetRoutesViaConnection(ctx context.Context, con *pgxpool.Conn, accountId string) ([]nmdata.Route, error) {
	rows, err := con.Query(ctx, GetRoutesQuery, accountId)
	if err != nil {
		return nil, err
	}

	routes, err := pgx.CollectRows(rows, pgx.RowToStructByName[route])
	if err != nil {
		return nil, err
	}

	toret := make([]nmdata.Route, 0, len(routes))
	for _, r := range routes {
		route := nmdata.Route{}
		err := networkmapdb.FromSqlTypesToSharedTypes(
			reflect.ValueOf(&r), reflect.ValueOf(&route))
		if err != nil {
			return nil, err
		}
		toret = append(toret, route)
	}
	return toret, nil
}

type route struct {
	ID                  string
	AccountID           sql.NullString
	PublicID            sql.NullString
	Network             json.RawMessage
	Domains             json.RawMessage
	KeepRoute           sql.NullBool
	NetID               sql.NullString
	Description         sql.NullString
	Peer                sql.NullString
	PeerID              sql.NullString
	PeerGroups          json.RawMessage
	NetworkType         sql.NullInt64
	Masquerade          sql.NullBool
	Metric              sql.NullInt64
	Enabled             sql.NullBool
	Groups              json.RawMessage
	AccessControlGroups json.RawMessage
	SkipAutoApply       sql.NullBool
}
