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
	select array_agg(id) from groups
	where account_id=$1 and name='All'
	`
)

func (pgc *PgStoreConn) GetAllowedUsers(ctx context.Context, accountId string) (map[string]struct{}, map[string][]string, error) {
	rows, err := pgc.Conn.Query(ctx, GetAllowedUserIdsQuery, accountId)
	if err != nil {
		return nil, nil, err
	}
	users, err := collectUsers(rows)
	if err != nil {
		return nil, nil, err
	}

	rows, err = pgc.Conn.Query(ctx, GetAllGroupIdQuery, accountId)
	if err != nil {
		return nil, nil, err
	}
	allGroupIds, err := collectAllGroupIds(rows)
	if err != nil {
		return nil, nil, err
	}

	userIdIdx, groupIdToUserIds := allowedUsers(users, allGroupIds)
	return userIdIdx, groupIdToUserIds, nil
}

func collectUsers(rows pgx.Rows) ([]user, error) {
	return pgx.CollectRows(rows, pgx.RowToStructByName[user])
}

func collectAllGroupIds(rows pgx.Rows) ([]string, error) {
	return pgx.CollectOneRow(rows, pgx.RowTo[[]string])
}

func allowedUsers(users []user, allGroupIds []string) (map[string]struct{}, map[string][]string) {
	userIdIdx := make(map[string]struct{})
	groupIdToUserIds := make(map[string][]string)
	for _, user := range users {
		userIdIdx[user.ID] = struct{}{}
		for _, groupId := range user.AutoGroups {
			groupIdToUserIds[groupId] = append(groupIdToUserIds[groupId], user.ID)
		}
		for _, allgid := range allGroupIds {
			groupIdToUserIds[allgid] = append(groupIdToUserIds[allgid], user.ID)
		}
	}

	return userIdIdx, groupIdToUserIds
}

type user struct {
	ID         string
	AutoGroups []string
}
