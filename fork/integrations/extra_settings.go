// SPDX-License-Identifier: BSD-3-Clause

package integrations

import (
	"context"
	"slices"

	"github.com/netbirdio/management-integrations/integrations/config"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/types"

	"github.com/netbirdio/netbird/management/server/integrations/extra_settings"
)

// ManagerImpl provides extra account settings from the process environment
// instead of a persisted store, mirroring the original module's surface.
type ManagerImpl struct {
}

// NewManager returns the extra settings manager. The event store argument is
// accepted for interface parity and unused, as nothing is persisted.
func NewManager(eventStore activity.Store) extra_settings.Manager {
	return &ManagerImpl{}
}

// GetExtraSettings returns the env-driven flow settings for any account.
// Non-flow fields keep their zero values, matching the original module.
func (m *ManagerImpl) GetExtraSettings(ctx context.Context, accountID string) (*types.ExtraSettings, error) {
	flow := config.LoadFlowSettings()
	return &types.ExtraSettings{
		FlowEnabled:              flow.Enabled,
		FlowGroups:               slices.Clone(flow.Groups),
		FlowPacketCounterEnabled: flow.Enabled,
		FlowENCollectionEnabled:  flow.ExitNodeCollection,
		FlowDnsCollectionEnabled: flow.DNSCollection,
	}, nil
}

// UpdateExtraSettings ignores updates: flow settings are deployment config
// (env vars) in this fork, not account data, so the REST toggles stay inert.
func (m *ManagerImpl) UpdateExtraSettings(ctx context.Context, accountID, userID string, accountExtraSettings *types.ExtraSettings) (bool, error) {
	return false, nil
}
