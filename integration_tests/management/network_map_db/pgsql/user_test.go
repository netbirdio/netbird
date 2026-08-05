package networkmap_pgsql

import (
	"context"
	"testing"

	networkmap_pgsql "github.com/netbirdio/netbird/management/internals/network_map_db/pgsql"
	"github.com/stretchr/testify/assert"
)

func TestGetAllowedUsers(t *testing.T) {
	ctx := context.TODO()

	execQuery(t, ctx,
		`insert into users (id, name, account_id, auto_groups, blocked, is_service_user)
		VALUES('user-1','user-1','account-1','["group-one-resource-id"]',false,false)`)
	execQuery(t, ctx,
		`insert into users (id, name, account_id, auto_groups, blocked, is_service_user)
		VALUES('user-2','user-2','account-1','["group-one-resource-id","group-two-resources-id"]',false,false)`)
	execQuery(t, ctx,
		`insert into users (id, name, account_id, auto_groups, blocked, is_service_user)
		VALUES('user-3','user-3','account-1','["group-two-resources-id"]',false,false)`)
	// shouldn't be included as it's blocked
	execQuery(t, ctx,
		`insert into users (id, name, account_id, auto_groups, blocked, is_service_user)
		VALUES('user-4','user-4','account-1','["group-two-resources-id"]',true,false)`)
	// shouldn't be included as it's a service_user
	execQuery(t, ctx,
		`insert into users (id, name, account_id, auto_groups, blocked, is_service_user)
		VALUES('user-5','user-5','account-1','["group-two-resources-id"]',false,true)`)
	execQuery(t, ctx,
		`insert into groups (id, name, account_id)
		VALUES('all-group-1','All','account-1')`)
	execQuery(t, ctx,
		`insert into groups (id, name, account_id)
		VALUES('all-group-2','All','account-1')`)
	execQuery(t, ctx,
		`insert into groups (id, name, account_id)
		VALUES('all-group-3','All','account-1')`)

	userIdx, groupIdToUserIds, err := networkmap_pgsql.GetAllowedUsersViaPgxConnection(ctx, conn(t, ctx), "account-1")
	assert.NoError(t, err)

	assert.Equal(t, userIdx, map[string]struct{}{
		"user-1": {},
		"user-2": {},
		"user-3": {},
	})
	assert.Equal(t, groupIdToUserIds, map[string][]string{
		"group-one-resource-id":  {"user-1", "user-2"},
		"group-two-resources-id": {"user-2", "user-3"},
		"all-group-1":            {"user-1", "user-2", "user-3"},
		"all-group-2":            {"user-1", "user-2", "user-3"},
		"all-group-3":            {"user-1", "user-2", "user-3"},
	})
}
