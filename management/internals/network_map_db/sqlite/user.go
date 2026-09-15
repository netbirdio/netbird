package networkmap_sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
)

const (
	GetAllowedUserIdsQuery = `
	select id, auto_groups
	from users
	where account_id=? and not blocked and not is_service_user
	`

	GetAllGroupIdQuery = `
	select id from groups
	where account_id=? and name='All'
	`
)

func (sc *SqliteStoreConn) GetAllowedUsers(ctx context.Context, accountId string) (map[string]struct{}, map[string][]string, error) {
	rows, err := sc.Conn.QueryContext(ctx, GetAllowedUserIdsQuery, accountId)
	if err != nil {
		return nil, nil, err
	}

	users, err := CollectRowsForSqlite[user](rows)
	if err != nil {
		return nil, nil, err
	}

	rows, err = sc.Conn.QueryContext(ctx, GetAllGroupIdQuery, accountId)
	if err != nil {
		return nil, nil, err
	}
	allGroupIds, err := collectAllGroupIds(rows)
	if err != nil {
		return nil, nil, err
	}

	userIdIdx := make(map[string]struct{})
	groupIdToUserIds := make(map[string][]string)
	for _, user := range users {
		for _, allgid := range allGroupIds {
			groupIdToUserIds[allgid] = append(groupIdToUserIds[allgid], user.ID)
		}
		userIdIdx[user.ID] = struct{}{}
		autogroups := make([]string, 0)
		if user.AutoGroups == nil {
			continue
		}
		if err := json.Unmarshal(user.AutoGroups, &autogroups); err != nil {
			return nil, nil, err
		}
		for _, groupId := range autogroups {
			groupIdToUserIds[groupId] = append(groupIdToUserIds[groupId], user.ID)
		}
	}

	return userIdIdx, groupIdToUserIds, nil
}

func collectAllGroupIds(rows *sql.Rows) ([]string, error) {
	defer rows.Close()
	var toret []string

	for rows.Next() {
		var id string
		err := rows.Scan(&id)
		if err != nil {
			return nil, err
		}
		toret = append(toret, id)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return toret, nil
}

type user struct {
	ID         string
	AutoGroups []byte
}
