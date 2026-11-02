package manager

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/server/store"
)

func TestCreateServiceTargetAccessWithoutActiveProxies(t *testing.T) {
	for _, action := range []rpservice.TargetAccessAction{
		rpservice.TargetAccessActionBlock,
		rpservice.TargetAccessActionBypass,
	} {
		t.Run(string(action), func(t *testing.T) {
			ctx := context.Background()
			mgr, testStore, _ := setupL4Test(t, nil)
			svc := &rpservice.Service{
				Name: "target access", Domain: "target.test.netbird.io", Mode: rpservice.ModeHTTP,
				Enabled: true,
				Targets: []*rpservice.Target{{
					AccountID: testAccountID, TargetId: testPeerID,
					TargetType: rpservice.TargetTypePeer, Protocol: "http", Port: 8080,
					Enabled: true, AccessAction: action,
				}},
			}
			created, err := mgr.CreateService(ctx, testAccountID, testUserID, svc)
			require.NoError(t, err)
			stored, err := testStore.GetServiceByID(ctx, store.LockingStrengthNone, testAccountID, created.ID)
			require.NoError(t, err)
			require.Len(t, stored.Targets, 1)
			assert.Equal(t, action, stored.Targets[0].AccessAction,
				"accepted target actions must survive persistence")
		})
	}
}

func TestUpdateServicePreservesOmittedTargetAccessAction(t *testing.T) {
	ctx := context.Background()
	mgr, testStore, _ := setupL4Test(t, nil)
	existing := seedService(t, testStore, "protected", "http", "target.test.netbird.io", testCluster, 0)
	existing.Targets[0].AccessAction = rpservice.TargetAccessActionBlock
	require.NoError(t, testStore.UpdateService(ctx, existing))

	updated := existing.Copy()
	updated.Name = "renamed by an older client"
	updated.Targets[0].AccessAction = rpservice.TargetAccessActionInherit
	updated.Targets[0].AccessActionProvided = false
	rootPath := "/"
	updated.Targets[0].Path = &rootPath
	_, err := mgr.UpdateService(ctx, testAccountID, testUserID, updated)
	require.NoError(t, err)
	stored, err := testStore.GetServiceByID(ctx, store.LockingStrengthNone, testAccountID, existing.ID)
	require.NoError(t, err)
	assert.Equal(t, updated.Name, stored.Name, "legacy updates must still apply unrelated edits")
	assert.Equal(t, rpservice.TargetAccessActionBlock, stored.Targets[0].AccessAction,
		"an omitted action must preserve the stored block across equivalent root locations")

	emptyPath := ""
	updated.Targets[0].Path = &emptyPath
	updated.Targets[0].AccessAction = rpservice.TargetAccessActionInherit
	_, err = mgr.UpdateService(ctx, testAccountID, testUserID, updated)
	require.NoError(t, err)
	stored, err = testStore.GetServiceByID(ctx, store.LockingStrengthNone, testAccountID, existing.ID)
	require.NoError(t, err)
	assert.Equal(t, rpservice.TargetAccessActionBlock, stored.Targets[0].AccessAction,
		"an older client's empty root location must preserve the stored block")

	updated.Targets[0].AccessAction = rpservice.TargetAccessActionInherit
	updated.Targets[0].AccessActionProvided = true
	_, err = mgr.UpdateService(ctx, testAccountID, testUserID, updated)
	require.NoError(t, err)
	stored, err = testStore.GetServiceByID(ctx, store.LockingStrengthNone, testAccountID, existing.ID)
	require.NoError(t, err)
	assert.Equal(t, rpservice.TargetAccessActionInherit, stored.Targets[0].AccessAction,
		"explicit inherit must clear the stored target block")
}

func TestUpdateServiceActivatesPreservedTargetAccess(t *testing.T) {
	ctx := context.Background()
	mgr, testStore, _ := setupL4Test(t, nil)
	existing := seedService(t, testStore, "protected", "http", "target.test.netbird.io", testCluster, 0)
	existing.Enabled = false
	existing.Targets[0].AccessAction = rpservice.TargetAccessActionBlock
	require.NoError(t, testStore.UpdateService(ctx, existing))

	updated := existing.Copy()
	updated.Enabled = true
	updated.Targets[0].AccessAction = rpservice.TargetAccessActionInherit
	updated.Targets[0].AccessActionProvided = false
	_, err := mgr.UpdateService(ctx, testAccountID, testUserID, updated)
	require.NoError(t, err)
	stored, err := testStore.GetServiceByID(ctx, store.LockingStrengthNone, testAccountID, existing.ID)
	require.NoError(t, err)
	assert.True(t, stored.Enabled, "activating target access must not require an active proxy")
	assert.Equal(t, rpservice.TargetAccessActionBlock, stored.Targets[0].AccessAction,
		"activation must retain an omitted stored access action")
}

func TestUpdateServiceValidatesPreservedTargetAccess(t *testing.T) {
	ctx := context.Background()
	mgr, testStore, _ := setupL4Test(t, nil)
	existing := seedService(t, testStore, "public", "http", "target.test.netbird.io", testCluster, 0)
	existing.Targets[0].AccessAction = rpservice.TargetAccessActionBypass
	require.NoError(t, testStore.UpdateService(ctx, existing))

	updated := existing.Copy()
	updated.Private = true
	updated.AccessGroups = []string{testGroupID}
	updated.Targets[0].AccessAction = rpservice.TargetAccessActionInherit
	updated.Targets[0].AccessActionProvided = false
	_, err := mgr.UpdateService(ctx, testAccountID, testUserID, updated)
	require.ErrorContains(t, err, "bypass access_action is not supported for private services")

	stored, err := testStore.GetServiceByID(ctx, store.LockingStrengthNone, testAccountID, existing.ID)
	require.NoError(t, err)
	assert.False(t, stored.Private, "an invalid preserved bypass must prevent the private-service update")
	assert.Equal(t, rpservice.TargetAccessActionBypass, stored.Targets[0].AccessAction,
		"a rejected update must retain the existing target action")
}

func TestUpdateServiceLegacyClientCannotRemoveControlledPath(t *testing.T) {
	for _, operation := range []string{"rename", "delete"} {
		t.Run(operation, func(t *testing.T) {
			ctx := context.Background()
			mgr, testStore, _ := setupL4Test(t, nil)
			existing := seedService(t, testStore, "protected", "http", "target.test.netbird.io", testCluster, 0)
			blockedPath := "/blocked"
			existing.Targets = append(existing.Targets, &rpservice.Target{
				AccountID: testAccountID, TargetId: testPeerID, TargetType: rpservice.TargetTypePeer,
				Protocol: "http", Port: 8080, Enabled: true, Path: &blockedPath,
				AccessAction: rpservice.TargetAccessActionBlock,
			})
			require.NoError(t, testStore.UpdateService(ctx, existing))

			updated := existing.Copy()
			updated.Targets[1].AccessAction = rpservice.TargetAccessActionInherit
			if operation == "rename" {
				renamedPath := "/renamed"
				updated.Targets[1].Path = &renamedPath
			} else {
				updated.Targets = updated.Targets[:1]
			}
			_, err := mgr.UpdateService(ctx, testAccountID, testUserID, updated)
			require.Error(t, err)
			stored, err := testStore.GetServiceByID(ctx, store.LockingStrengthNone, testAccountID, existing.ID)
			require.NoError(t, err)
			require.Len(t, stored.Targets, 2, "a legacy structural edit must retain the controlled target")
			var blocked *rpservice.Target
			for _, target := range stored.Targets {
				if effectiveTargetPath(target) == blockedPath {
					blocked = target
				}
			}
			require.NotNil(t, blocked, "the original controlled location must still exist")
			assert.Equal(t, rpservice.TargetAccessActionBlock, blocked.AccessAction,
				"a rejected legacy edit must not erase the block action")

			updated.Targets[0].AccessAction = rpservice.TargetAccessActionInherit
			updated.Targets[0].AccessActionProvided = true
			_, err = mgr.UpdateService(ctx, testAccountID, testUserID, updated)
			require.NoError(t, err)
			stored, err = testStore.GetServiceByID(ctx, store.LockingStrengthNone, testAccountID, existing.ID)
			require.NoError(t, err)
			assert.False(t, stored.HasTargetAccessControl(),
				"a feature-aware client must be able to intentionally remove or rename the controlled path")
		})
	}
}

func TestPreserveTargetAccessActionsExplicitUpdate(t *testing.T) {
	existing := &rpservice.Service{Targets: []*rpservice.Target{
		{Enabled: true, AccessAction: rpservice.TargetAccessActionBlock},
		{Enabled: false, AccessAction: rpservice.TargetAccessActionInherit},
	}}
	updated := &rpservice.Service{Targets: []*rpservice.Target{
		{Enabled: true, AccessAction: rpservice.TargetAccessActionBypass, AccessActionProvided: true},
		{Enabled: false, AccessAction: rpservice.TargetAccessActionInherit, AccessActionProvided: true},
	}}
	require.NoError(t, preserveTargetAccessActions(updated, existing))
	assert.Equal(t, rpservice.TargetAccessActionBypass, updated.Targets[0].AccessAction,
		"explicit actions must not need an ambiguous location-based legacy merge")

	updated.Targets[0].AccessActionProvided = false
	assert.Error(t, preserveTargetAccessActions(updated, existing),
		"an omitted action must be rejected when its stored location is ambiguous")

	existing.Targets = existing.Targets[:1]
	updated.Targets = nil
	assert.Error(t, preserveTargetAccessActions(updated, existing),
		"an empty target list must not count as an explicit removal of the stored block")
}
