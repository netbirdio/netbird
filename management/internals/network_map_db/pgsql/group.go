package networkmap_pgsql

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/jackc/pgx/v5"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

const (
	GetGroupsQuery = `
	select name, public_id, resources from groups where account_id=$1
	`
)

func (pg *PgStore) GetGroups(ctx context.Context, accountId string) ([]nmdata.Group, error) {
	rows, err := pg.pool.Query(ctx, GetGroupsQuery, accountId)
	if err != nil {
		return nil, err
	}

	var (
		group                     nmdata.Group
		name, publicId, resources sql.NullString
	)

	groups, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (nmdata.Group, error) {
		err := row.Scan(&name, &publicId, &resources)
		if err != nil {
			return group, err
		}

		if name.Valid {
			group.Name = name.String
		}
		if publicId.Valid {
			group.PublicID = publicId.String
		}
		if resources.Valid {
			groupResources := make([]nmdata.Resource, 0)
			err := json.Unmarshal([]byte(resources.String), &groupResources)
			if err != nil {
				return group, err
			}
			group.Resources = groupResources
		}
		return group, nil
	})

	return groups, err
}
