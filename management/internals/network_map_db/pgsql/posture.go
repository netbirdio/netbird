package networkmap_pgsql

import (
	"context"
	"encoding/json"
	"reflect"

	"github.com/jackc/pgx/v5"
	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

const (
	GetPostureChecksQuery = `
	select id, checks
	from posture_checks
	where account_id=$1
	`
)

func (pg *PgStore) GetPostureChecks(ctx context.Context, accountId string) ([]nmdata.PostureChecks, error) {
	rows, err := pg.pool.Query(ctx, GetPostureChecksQuery, accountId)
	if err != nil {
		return nil, err
	}

	checks, err := pgx.CollectRows(rows, pgx.RowToStructByName[posturechecks])
	if err != nil {
		return nil, err
	}

	toret := make([]nmdata.PostureChecks, 0, len(checks))
	for _, c := range checks {
		checks := nmdata.PostureChecks{}
		err := networkmapdb.FromSqlTypesToSharedTypes(reflect.ValueOf(&c), reflect.ValueOf(&checks))
		if err != nil {
			return nil, err
		}
		toret = append(toret, checks)
	}

	return toret, nil
}

type posturechecks struct {
	ID     string
	Checks json.RawMessage
}
