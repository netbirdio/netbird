package manager

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric/noop"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	proxymanager "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy/manager"
	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/status"
)

func TestCreateServiceTargetAccessControlCapability(t *testing.T) {
	for _, tc := range []struct {
		name      string
		capable   *bool
		legacy    bool
		enabled   bool
		wantError bool
	}{
		{name: "capable cluster", capable: boolPtr(true), enabled: true},
		{name: "mixed cluster", capable: boolPtr(true), legacy: true, enabled: true, wantError: true},
		{name: "unsupported cluster", capable: boolPtr(false), enabled: true, wantError: true},
		{name: "unreported capability", enabled: true, wantError: true},
		{name: "disabled configuration", enabled: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			mgr, testStore, _ := setupL4Test(t, nil)
			require.NoError(t, testStore.SaveProxy(ctx, &proxy.Proxy{
				ID: "current", ClusterAddress: testCluster,
				Status: proxy.StatusConnected, LastSeen: time.Now(),
				Capabilities: proxy.Capabilities{SupportsTargetAccessControl: tc.capable},
			}))
			if tc.legacy {
				require.NoError(t, testStore.SaveProxy(ctx, &proxy.Proxy{
					ID: "legacy", ClusterAddress: testCluster,
					Status: proxy.StatusConnected, LastSeen: time.Now(),
				}))
			}
			svc := &rpservice.Service{
				Name: "target access", Domain: "target.test.netbird.io", Mode: rpservice.ModeHTTP,
				Enabled: tc.enabled,
				Targets: []*rpservice.Target{{
					AccountID: testAccountID, TargetId: testPeerID,
					TargetType: rpservice.TargetTypePeer, Protocol: "http", Port: 8080,
					Enabled: true, AccessAction: rpservice.TargetAccessActionBlock,
				}},
			}
			created, err := mgr.CreateService(ctx, testAccountID, testUserID, svc)
			if tc.wantError {
				require.Error(t, err)
				parsed, ok := status.FromError(err)
				require.True(t, ok, "capability rejection must use a structured status")
				assert.Equal(t, status.PreconditionFailed, parsed.Type(), "unsupported clusters must fail activation")
				_, err := testStore.GetServiceByID(ctx, store.LockingStrengthNone, testAccountID, svc.ID)
				assert.Error(t, err, "a rejected service must not be persisted")
				return
			}
			require.NoError(t, err)
			stored, err := testStore.GetServiceByID(ctx, store.LockingStrengthNone, testAccountID, created.ID)
			require.NoError(t, err)
			require.Len(t, stored.Targets, 1)
			assert.Equal(t, rpservice.TargetAccessActionBlock, stored.Targets[0].AccessAction,
				"accepted target actions must survive persistence")
		})
	}
}

func TestUpdateServicePreservesOmittedTargetAccessAction(t *testing.T) {
	ctx := context.Background()
	mgr, testStore, _ := setupL4Test(t, nil)
	capable := true
	require.NoError(t, testStore.SaveProxy(ctx, &proxy.Proxy{
		ID: "current", ClusterAddress: testCluster,
		Status: proxy.StatusConnected, LastSeen: time.Now(),
		Capabilities: proxy.Capabilities{SupportsTargetAccessControl: &capable},
	}))
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

func TestUpdateServiceCannotActivateTargetAccessOnLegacyCluster(t *testing.T) {
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
	require.Error(t, err)
	stored, err := testStore.GetServiceByID(ctx, store.LockingStrengthNone, testAccountID, existing.ID)
	require.NoError(t, err)
	assert.False(t, stored.Enabled, "an older client must not activate an unenforceable policy")
	assert.Equal(t, rpservice.TargetAccessActionBlock, stored.Targets[0].AccessAction,
		"a failed activation must retain the stored access action")
}

func TestGetClustersReportsTargetAccessControlCapability(t *testing.T) {
	ctx := context.Background()
	mgr, testStore, _ := setupL4Test(t, nil)
	proxyManager, err := proxymanager.NewManager(testStore, noop.NewMeterProvider().Meter("test"))
	require.NoError(t, err)
	mgr.capabilities = proxyManager
	capable := true
	require.NoError(t, testStore.SaveProxy(ctx, &proxy.Proxy{
		ID: "current", ClusterAddress: testCluster,
		Status: proxy.StatusConnected, LastSeen: time.Now(),
		Capabilities: proxy.Capabilities{SupportsTargetAccessControl: &capable},
	}))
	clusters, err := mgr.GetClusters(ctx, testAccountID, testUserID)
	require.NoError(t, err)
	require.Len(t, clusters, 1)
	require.NotNil(t, clusters[0].SupportsTargetAccessControl)
	assert.True(t, *clusters[0].SupportsTargetAccessControl,
		"cluster listings must expose the stored target access capability to clients")
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
