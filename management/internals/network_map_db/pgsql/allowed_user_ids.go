package networkmap_pgsql

import (
	"context"

	"github.com/jackc/pgx/v5"
)

const (
	GetAllowedUserIdsQuery = `
	select id
	from users
	where account_id=$1 and not blocked and not is_service_user
	`
)

func (pg *PgStore) GetAllowedUserIds(ctx context.Context, accountId string) (map[string]struct{}, error) {
	c, err := pg.Pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	return GetGetAllowedUserIdsViaPgxConnection(ctx, c.Conn(), accountId)
}

func GetGetAllowedUserIdsViaPgxConnection(ctx context.Context, con *pgx.Conn, accountId string) (map[string]struct{}, error) {
	rows, err := con.Query(ctx, GetAllowedUserIdsQuery, accountId)
	if err != nil {
		return nil, err
	}

	toret := make(map[string]struct{})
	var id string
	_, err = pgx.ForEachRow(rows, []any{&id}, func() error {
		toret[id] = struct{}{}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return toret, nil
}
