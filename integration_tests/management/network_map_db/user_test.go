//go:build integration

package networkmap_pgsql

import (
	"context"
	"testing"

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
	// empty auto_groups; shouldn't error out
	execQuery(t, ctx,
		`insert into users (id, name, account_id, auto_groups, blocked, is_service_user)
		VALUES('user-31','user-31','account-1','[]',false,false)`)
	// null auto_groups; shouldn't error out
	execQuery(t, ctx,
		`insert into users (id, name, account_id, auto_groups, blocked, is_service_user)
		VALUES('user-32','user-32','account-1',null,false,false)`)
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

	userIdx, groupIdToUserIds, err := conn(t, ctx).GetAllowedUsers(ctx, "account-1")
	assert.NoError(t, err)

	assert.Equal(t, userIdx, map[string]struct{}{
		"user-1":  {},
		"user-2":  {},
		"user-3":  {},
		"user-31": {},
		"user-32": {},
	})
	assert.Equal(t, groupIdToUserIds, map[string][]string{
		"group-one-resource-id":  {"user-1", "user-2"},
		"group-two-resources-id": {"user-2", "user-3"},
		"all-group-1":            {"user-1", "user-2", "user-3", "user-31", "user-32"},
		"all-group-2":            {"user-1", "user-2", "user-3", "user-31", "user-32"},
		"all-group-3":            {"user-1", "user-2", "user-3", "user-31", "user-32"},
	})
}
