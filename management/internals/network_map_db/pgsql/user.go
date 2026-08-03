package networkmap_pgsql

import (
	"context"

	"github.com/jackc/pgx/v5"
)

const (
	GetAllowedUserIdsQuery = `
	select id, array (select json_array_elements_text(auto_groups::json)) as auto_groups 
	from users
	where account_id=$1 and not blocked and not is_service_user
	`
)

func (pg *PgStore) GetAllowedUsers(ctx context.Context, accountId string) (map[string]struct{}, map[string][]string, error) {
	c, err := pg.Pool.Acquire(ctx)
	if err != nil {
		return nil, nil, err
	}
	return GetAllowedUsersViaPgxConnection(ctx, c.Conn(), accountId)
}

func GetAllowedUsersViaPgxConnection(ctx context.Context, con *pgx.Conn, accountId string) (map[string]struct{}, map[string][]string, error) {
	rows, err := con.Query(ctx, GetAllowedUserIdsQuery, accountId)
	if err != nil {
		return nil, nil, err
	}

	users, err := pgx.CollectRows(rows, pgx.RowToStructByName[user])
	if err != nil {
		return nil, nil, err
	}

	userIdIdx := make(map[string]struct{})
	groupIdToUserIds := make(map[string][]string)
	for _, user := range users {
		userIdIdx[user.ID] = struct{}{}
		for _, groupId := range user.AutoGroups {
			groupIdToUserIds[groupId] = append(groupIdToUserIds[groupId], user.ID)
		}
	}

	return userIdIdx, groupIdToUserIds, nil
}

type user struct {
	ID         string
	AutoGroups []string
}
