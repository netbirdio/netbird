package agentnetwork

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rpproxy "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/server/store"
)

// TestSynthesizeServices_RealStore_LogCollectionOff_SuppressesAccessLog drives the
// happy default: account settings ship with EnableLogCollection=false, so the
// synthesised target opts out of access-log emission (DisableAccessLog=true) and
// the proto mapping the proxy receives reflects that.
func TestSynthesizeServices_RealStore_LogCollectionOff_SuppressesAccessLog(t *testing.T) {
	ctx := context.Background()
	s, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err, "real sqlite test store must come up")
	defer cleanup()

	require.NoError(t, s.SaveAgentNetworkSettings(ctx, newSynthTestSettings()))
	provider := newSynthTestProvider()
	require.NoError(t, s.SaveAgentNetworkProvider(ctx, provider))
	require.NoError(t, s.SaveAgentNetworkPolicy(ctx, newSynthTestPolicy(provider.ID, "grp-eng", "")))

	services, err := SynthesizeServices(ctx, s, testAccountID)
	require.NoError(t, err)
	require.Len(t, services, 1, "exactly one synth service expected")
	require.NotEmpty(t, services[0].Targets, "synth service must carry a target")
	assert.True(t, services[0].Targets[0].Options.DisableAccessLog,
		"EnableLogCollection=false (default) must produce DisableAccessLog=true on the synth target")

	mapping := services[0].ToProtoMapping(rpservice.Update, "", rpproxy.OIDCValidationConfig{})
	require.NotEmpty(t, mapping.GetPath(), "proto mapping must carry a path")
	assert.True(t, mapping.GetPath()[0].GetOptions().GetDisableAccessLog(),
		"proto mapping must propagate DisableAccessLog=true so the proxy suppresses access-log emission")
}

// TestSynthesizeServices_RealStore_LogCollectionOn_PermitsAccessLog asserts the
// inverse: once the account opts in, the synth target leaves DisableAccessLog
// at its default false and the proto wire stays unset.
func TestSynthesizeServices_RealStore_LogCollectionOn_PermitsAccessLog(t *testing.T) {
	ctx := context.Background()
	s, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err, "real sqlite test store must come up")
	defer cleanup()

	settings := newSynthTestSettings()
	settings.EnableLogCollection = true
	require.NoError(t, s.SaveAgentNetworkSettings(ctx, settings))
	provider := newSynthTestProvider()
	require.NoError(t, s.SaveAgentNetworkProvider(ctx, provider))
	require.NoError(t, s.SaveAgentNetworkPolicy(ctx, newSynthTestPolicy(provider.ID, "grp-eng", "")))

	services, err := SynthesizeServices(ctx, s, testAccountID)
	require.NoError(t, err)
	require.Len(t, services, 1, "exactly one synth service expected")
	require.NotEmpty(t, services[0].Targets, "synth service must carry a target")
	assert.False(t, services[0].Targets[0].Options.DisableAccessLog,
		"EnableLogCollection=true must leave DisableAccessLog=false on the synth target")

	mapping := services[0].ToProtoMapping(rpservice.Update, "", rpproxy.OIDCValidationConfig{})
	require.NotEmpty(t, mapping.GetPath(), "proto mapping must carry a path")
	assert.False(t, mapping.GetPath()[0].GetOptions().GetDisableAccessLog(),
		"proto mapping must propagate DisableAccessLog=false so access-log emission stays on")
}
