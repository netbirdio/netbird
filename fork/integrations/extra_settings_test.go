// SPDX-License-Identifier: BSD-3-Clause

package integrations

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/management-integrations/integrations/config"

	"github.com/netbirdio/netbird/management/server/types"
)

// The flow environment must be configured before the first GetExtraSettings
// call: LoadFlowSettings parses it exactly once per process.
func TestGetExtraSettings_MapsFlowEnv(t *testing.T) {
	t.Setenv(config.EnvFlowGroups, "grp-flow-a, grp-flow-b")
	t.Setenv(config.EnvFlowReceiverURL, "flows.example.com:443")
	t.Setenv(config.EnvFlowSigningKey, "s3cr3t")
	t.Setenv(config.EnvFlowDNSCollection, "true")
	t.Setenv(config.EnvFlowExitNodeCollection, "false")

	m := NewManager(nil)

	settings, err := m.GetExtraSettings(context.Background(), "any-account")
	require.NoError(t, err)
	require.NotNil(t, settings)

	assert.True(t, settings.FlowEnabled)
	assert.True(t, settings.FlowPacketCounterEnabled, "counters follow the enabled state")
	assert.Equal(t, []string{"grp-flow-a", "grp-flow-b"}, settings.FlowGroups)
	assert.True(t, settings.FlowDnsCollectionEnabled)
	assert.False(t, settings.FlowENCollectionEnabled)

	settings.FlowGroups[0] = "mutated"
	fresh, err := m.GetExtraSettings(context.Background(), "any-account")
	require.NoError(t, err)
	assert.Equal(t, "grp-flow-a", fresh.FlowGroups[0], "each call must hand out a copy, not the cached slice")
}

func TestUpdateExtraSettings_IsInert(t *testing.T) {
	m := NewManager(nil)

	events, err := m.UpdateExtraSettings(context.Background(), "account", "user", &types.ExtraSettings{FlowEnabled: true})

	assert.NoError(t, err)
	assert.False(t, events, "env-driven settings never change, so no peer updates are triggered")
}
