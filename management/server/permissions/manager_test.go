package permissions

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/permissions/roles"
	"github.com/netbirdio/netbird/management/server/types"
)

func TestValidateRoleModuleAccessSubmoduleCascade(t *testing.T) {
	manager := NewManager(nil)
	ctx := context.Background()

	fullAccess := map[operations.Operation]bool{
		operations.Read:   true,
		operations.Create: true,
		operations.Update: true,
		operations.Delete: true,
	}
	readOnly := map[operations.Operation]bool{
		operations.Read:   true,
		operations.Create: false,
		operations.Update: false,
		operations.Delete: false,
	}
	denyAll := map[operations.Operation]bool{
		operations.Read:   false,
		operations.Create: false,
		operations.Update: false,
		operations.Delete: false,
	}

	t.Run("parent grant covers submodules", func(t *testing.T) {
		role := roles.RolePermissions{
			AutoAllowNew: denyAll,
			Permissions:  roles.Permissions{modules.AgentNetwork: fullAccess},
		}
		assert.True(t, manager.ValidateRoleModuleAccess(ctx, "account", role, modules.AgentNetworkProviders, operations.Create),
			"parent full grant should allow create on a submodule")
		assert.True(t, manager.ValidateRoleModuleAccess(ctx, "account", role, modules.AgentNetworkLogs, operations.Read),
			"parent full grant should allow read on a submodule")
	})

	t.Run("submodule grant does not leak to parent or siblings", func(t *testing.T) {
		role := roles.RolePermissions{
			AutoAllowNew: denyAll,
			Permissions:  roles.Permissions{modules.AgentNetworkUsage: readOnly},
		}
		assert.True(t, manager.ValidateRoleModuleAccess(ctx, "account", role, modules.AgentNetworkUsage, operations.Read),
			"explicit submodule read should be allowed")
		assert.False(t, manager.ValidateRoleModuleAccess(ctx, "account", role, modules.AgentNetworkUsage, operations.Create),
			"read-only submodule grant should not allow create")
		assert.False(t, manager.ValidateRoleModuleAccess(ctx, "account", role, modules.AgentNetwork, operations.Read),
			"submodule grant should not grant the parent module")
		assert.False(t, manager.ValidateRoleModuleAccess(ctx, "account", role, modules.AgentNetworkProviders, operations.Read),
			"submodule grant should not grant a sibling submodule")
	})

	t.Run("explicit submodule entry wins over parent grant", func(t *testing.T) {
		role := roles.RolePermissions{
			AutoAllowNew: denyAll,
			Permissions: roles.Permissions{
				modules.AgentNetwork:     fullAccess,
				modules.AgentNetworkLogs: denyAll,
			},
		}
		assert.False(t, manager.ValidateRoleModuleAccess(ctx, "account", role, modules.AgentNetworkLogs, operations.Read),
			"explicit submodule deny should override the parent grant")
		assert.True(t, manager.ValidateRoleModuleAccess(ctx, "account", role, modules.AgentNetworkUsage, operations.Read),
			"sibling submodules should still resolve through the parent grant")
	})

	t.Run("auto allow applies when neither submodule nor parent is granted", func(t *testing.T) {
		role := roles.RolePermissions{
			AutoAllowNew: readOnly,
		}
		assert.True(t, manager.ValidateRoleModuleAccess(ctx, "account", role, modules.AgentNetworkProviders, operations.Read),
			"auto-allow read should apply to submodules")
		assert.False(t, manager.ValidateRoleModuleAccess(ctx, "account", role, modules.AgentNetworkProviders, operations.Delete),
			"auto-allow should not grant unlisted operations")
	})
}

// TestExistingRolesKeepAgentNetworkBehaviorOnSubmodules pins the behavior the
// submodule split must not change: every built-in role resolves the new
// submodules exactly as it resolved the agent_network module before.
func TestExistingRolesKeepAgentNetworkBehaviorOnSubmodules(t *testing.T) {
	manager := NewManager(nil)
	ctx := context.Background()

	submodules := []modules.Module{
		modules.AgentNetworkProviders,
		modules.AgentNetworkPolicies,
		modules.AgentNetworkGuardrails,
		modules.AgentNetworkBudgets,
		modules.AgentNetworkUsage,
		modules.AgentNetworkLogs,
		modules.AgentNetworkSettings,
	}
	allOperations := []operations.Operation{operations.Read, operations.Create, operations.Update, operations.Delete}

	for _, role := range []types.UserRole{types.UserRoleOwner, types.UserRoleAdmin, types.UserRoleAuditor, types.UserRoleNetworkAdmin, types.UserRoleUser} {
		rolePermissions, ok := roles.RolesMap[role]
		require.True(t, ok, "role %s must exist in RolesMap", role)

		for _, sub := range submodules {
			for _, op := range allOperations {
				expected := manager.ValidateRoleModuleAccess(ctx, "account", rolePermissions, modules.AgentNetwork, op)
				actual := manager.ValidateRoleModuleAccess(ctx, "account", rolePermissions, sub, op)
				assert.Equal(t, expected, actual, "role %s: %s on %s should match the agent_network module", role, op, sub)
			}
		}
	}
}

func TestGetPermissionsByRoleIncludesSubmodules(t *testing.T) {
	manager := NewManager(nil)
	ctx := context.Background()

	permissions, err := manager.GetPermissionsByRole(ctx, types.UserRoleAuditor)
	require.NoError(t, err, "auditor role must resolve")

	usage, ok := permissions[modules.AgentNetworkUsage]
	require.True(t, ok, "permissions map should contain the usage submodule")
	assert.True(t, usage[operations.Read], "auditor should read the usage submodule")
	assert.False(t, usage[operations.Update], "auditor should not update the usage submodule")

	adminPermissions, err := manager.GetPermissionsByRole(ctx, types.UserRoleAdmin)
	require.NoError(t, err, "admin role must resolve")
	providers, ok := adminPermissions[modules.AgentNetworkProviders]
	require.True(t, ok, "permissions map should contain the providers submodule")
	assert.True(t, providers[operations.Delete], "admin should delete on the providers submodule")
}
