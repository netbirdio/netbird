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

var allOps = []operations.Operation{operations.Read, operations.Create, operations.Update, operations.Delete}

// TestAgentNetworkAdminRole pins the delegated-admin contract: full control
// over the whole agent_network area (parent grant cascades to every
// submodule), read-only on the account objects needed to build policies,
// and nothing else in the account.
func TestAgentNetworkAdminRole(t *testing.T) {
	manager := NewManager(nil)
	ctx := context.Background()

	role, ok := roles.RolesMap[types.UserRoleAgentNetworkAdmin]
	require.True(t, ok, "agent_network_admin must exist in RolesMap")

	agentNetworkModules := []modules.Module{
		modules.AgentNetwork,
		modules.AgentNetworkProviders,
		modules.AgentNetworkPolicies,
		modules.AgentNetworkGuardrails,
		modules.AgentNetworkBudgets,
		modules.AgentNetworkUsage,
		modules.AgentNetworkLogs,
		modules.AgentNetworkSettings,
	}
	for _, m := range agentNetworkModules {
		for _, op := range allOps {
			assert.True(t, manager.ValidateRoleModuleAccess(ctx, "account", role, m, op),
				"agent_network_admin must have %s on %s", op, m)
		}
	}

	for _, m := range []modules.Module{modules.Users, modules.Groups, modules.Peers, modules.Accounts} {
		assert.True(t, manager.ValidateRoleModuleAccess(ctx, "account", role, m, operations.Read),
			"agent_network_admin must read %s to build policies", m)
		for _, op := range []operations.Operation{operations.Create, operations.Update, operations.Delete} {
			assert.False(t, manager.ValidateRoleModuleAccess(ctx, "account", role, m, op),
				"agent_network_admin must not have %s on %s", op, m)
		}
	}

	for _, m := range []modules.Module{modules.Networks, modules.Dns, modules.SetupKeys, modules.Routes, modules.Settings} {
		for _, op := range allOps {
			assert.False(t, manager.ValidateRoleModuleAccess(ctx, "account", role, m, op),
				"agent_network_admin must not have %s on %s", op, m)
		}
	}
}

// TestUsageViewerRole pins the least-privilege cost role: read on the
// aggregated usage overview and nothing else — no providers, no policies,
// no request-level logs (which can contain captured prompts), nothing in
// the rest of the account.
func TestUsageViewerRole(t *testing.T) {
	manager := NewManager(nil)
	ctx := context.Background()

	role, ok := roles.RolesMap[types.UserRoleUsageViewer]
	require.True(t, ok, "usage_viewer must exist in RolesMap")

	assert.True(t, manager.ValidateRoleModuleAccess(ctx, "account", role, modules.AgentNetworkUsage, operations.Read),
		"usage_viewer must read the usage overview")
	for _, op := range []operations.Operation{operations.Create, operations.Update, operations.Delete} {
		assert.False(t, manager.ValidateRoleModuleAccess(ctx, "account", role, modules.AgentNetworkUsage, op),
			"usage_viewer must not have %s on usage", op)
	}

	denied := []modules.Module{
		modules.AgentNetwork,
		modules.AgentNetworkProviders,
		modules.AgentNetworkPolicies,
		modules.AgentNetworkGuardrails,
		modules.AgentNetworkBudgets,
		modules.AgentNetworkLogs,
		modules.AgentNetworkSettings,
		modules.Networks,
		modules.Users,
		modules.SetupKeys,
	}
	for _, m := range denied {
		for _, op := range allOps {
			assert.False(t, manager.ValidateRoleModuleAccess(ctx, "account", role, m, op),
				"usage_viewer must not have %s on %s", op, m)
		}
	}
}

// TestBillingAdminRoleResolves pins that billing_admin has a proper entry
// in the permission map. Its plan/seat/invoice permissions are enforced
// outside this map; management-side it carries the regular User baseline
// instead of failing role resolution.
func TestBillingAdminRoleResolves(t *testing.T) {
	manager := NewManager(nil)
	ctx := context.Background()

	role, ok := roles.RolesMap[types.UserRoleBillingAdmin]
	require.True(t, ok, "billing_admin must exist in RolesMap")

	permissions, err := manager.GetPermissionsByRole(ctx, types.UserRoleBillingAdmin)
	require.NoError(t, err, "billing_admin role must resolve")
	require.NotEmpty(t, permissions)

	for _, m := range []modules.Module{modules.AgentNetwork, modules.Networks, modules.Users, modules.Peers} {
		for _, op := range allOps {
			assert.False(t, manager.ValidateRoleModuleAccess(ctx, "account", role, m, op),
				"billing_admin must not have %s on %s", op, m)
		}
	}
}

// TestNewRolesParse pins the API role strings, which are permanent once
// released.
func TestNewRolesParse(t *testing.T) {
	assert.Equal(t, types.UserRoleAgentNetworkAdmin, types.StrRoleToUserRole("agent_network_admin"))
	assert.Equal(t, types.UserRoleUsageViewer, types.StrRoleToUserRole("usage_viewer"))
	assert.Equal(t, types.UserRoleBillingAdmin, types.StrRoleToUserRole("billing_admin"))
}
