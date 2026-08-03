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

	GetAllGroupIdQuery = `
	select id from groups
	where account_id=$1 and name='All'
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

	rows, err = con.Query(ctx, GetAllGroupIdQuery, accountId)
	if err != nil {
		return nil, nil, err
	}
	allGroupIds, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, nil, err
	}
	allGroupId := ""
	if len(allGroupIds) > 0 {
		allGroupId = allGroupIds[0]
	}

	userIdIdx := make(map[string]struct{})
	groupIdToUserIds := make(map[string][]string)
	for _, user := range users {
		userIdIdx[user.ID] = struct{}{}
		for _, groupId := range user.AutoGroups {
			groupIdToUserIds[groupId] = append(groupIdToUserIds[groupId], user.ID)
		}
		if allGroupId != "" {
			groupIdToUserIds[allGroupId] = append(groupIdToUserIds[allGroupId], user.ID)
		}
	}

	return userIdIdx, groupIdToUserIds, nil
}

type user struct {
	ID         string
	AutoGroups []string
}
