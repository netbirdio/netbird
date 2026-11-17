package types_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbdns "github.com/netbirdio/netbird/dns"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
)

// helper: marks the given peer as components-capable.
func markCapable(p *nbpeer.Peer) {
	p.Meta.Capabilities = append(p.Meta.Capabilities, nbpeer.PeerCapabilityComponentNetworkMap)
}

func TestGetPeerNetworkMapResult_CapablePeerGetsComponents(t *testing.T) {
	account, validatedPeers := scalableTestAccount(10, 2)
	markCapable(account.Peers["peer-0"])

	resourcePolicies := account.GetResourcePoliciesMap()
	routers := account.GetResourceRoutersMap()
	groupIDToUserIDs := account.GetActiveGroupUsers()

	result := account.GetPeerNetworkMapResult(
		context.Background(),
		"peer-0",
		false, // componentsDisabled
		nbdns.CustomZone{},
		nil,
		validatedPeers,
		resourcePolicies,
		routers,
		nil,
		groupIDToUserIDs,
	)

	require.True(t, result.IsComponents(), "capable peer must get the components shape")
	assert.Nil(t, result.NetworkMap)
	require.NotNil(t, result.Components)
	assert.Equal(t, "peer-0", result.Components.PeerID)
}

func TestGetPeerNetworkMapResult_LegacyPeerGetsNetworkMap(t *testing.T) {
	account, validatedPeers := scalableTestAccount(10, 2)
	// peer-0 left without the component capability

	resourcePolicies := account.GetResourcePoliciesMap()
	routers := account.GetResourceRoutersMap()
	groupIDToUserIDs := account.GetActiveGroupUsers()

	result := account.GetPeerNetworkMapResult(
		context.Background(),
		"peer-0",
		false,
		nbdns.CustomZone{},
		nil,
		validatedPeers,
		resourcePolicies,
		routers,
		nil,
		groupIDToUserIDs,
	)

	assert.False(t, result.IsComponents())
	assert.Nil(t, result.Components)
	require.NotNil(t, result.NetworkMap, "legacy peer must get a NetworkMap")
}

func TestGetPeerNetworkMapResult_KillSwitchOverridesCapability(t *testing.T) {
	// Capable peer + componentsDisabled=true → falls back to legacy.
	account, validatedPeers := scalableTestAccount(10, 2)
	markCapable(account.Peers["peer-0"])

	resourcePolicies := account.GetResourcePoliciesMap()
	routers := account.GetResourceRoutersMap()
	groupIDToUserIDs := account.GetActiveGroupUsers()

	result := account.GetPeerNetworkMapResult(
		context.Background(),
		"peer-0",
		true, // componentsDisabled = true (kill switch)
		nbdns.CustomZone{},
		nil,
		validatedPeers,
		resourcePolicies,
		routers,
		nil,
		groupIDToUserIDs,
	)

	assert.False(t, result.IsComponents(), "kill switch must force legacy NetworkMap path")
	assert.Nil(t, result.Components)
	require.NotNil(t, result.NetworkMap)
}

func TestPeerNetworkMapResult_IsComponents(t *testing.T) {
	assert.True(t, types.PeerNetworkMapResult{Components: &types.NetworkMapComponents{}}.IsComponents())
	assert.False(t, types.PeerNetworkMapResult{NetworkMap: &types.NetworkMap{}}.IsComponents())
	assert.False(t, types.PeerNetworkMapResult{}.IsComponents())
}
