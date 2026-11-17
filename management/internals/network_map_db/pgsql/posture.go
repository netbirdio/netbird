package networkmap_pgsql

import (
	"context"
	"reflect"

	"github.com/jackc/pgx/v5"
	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

const (
	GetPostureChecksQuery = `
	select id, public_id, checks
	from posture_checks
	where account_id=$1
	`
)

func (pgc *PgStoreConn) GetPostureChecks(ctx context.Context, accountId string) ([]nmdata.PostureChecks, map[string]string, error) {
	rows, err := pgc.Conn.Query(ctx, GetPostureChecksQuery, accountId)
	if err != nil {
		return nil, nil, err
	}

	checks, err := pgx.CollectRows(rows, pgx.RowToStructByName[networkmapdb.PostureChecks])
	if err != nil {
		return nil, nil, err
	}

	toret := make([]nmdata.PostureChecks, 0, len(checks))
	idToPublicIDIdx := make(map[string]string)
	for _, c := range checks {
		checks := nmdata.PostureChecks{}
		err := networkmapdb.FromSqlTypesToSharedTypes(reflect.ValueOf(&c), reflect.ValueOf(&checks))
		if err != nil {
			return nil, nil, err
		}
		toret = append(toret, checks)
		idToPublicIDIdx[checks.ID] = c.PublicID.String
	}

	return toret, idToPublicIDIdx, nil
}
