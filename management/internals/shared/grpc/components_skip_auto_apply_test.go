package grpc

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/networkmap"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

// TestNetworkResourceSkipAutoApply_RoundTrip sends two subnet resources through the
// envelope the way a components client receives them: one marked skip auto apply and one
// not. The client builds routes from them locally, and the flag must reach those routes.
func TestNetworkResourceSkipAutoApply_RoundTrip(t *testing.T) {
	client := &nmdata.Peer{ID: "peer-client", Key: testWgKeyA, IP: netip.MustParseAddr("100.64.0.1"), DNSLabel: "client"}
	router := &nmdata.Peer{ID: "peer-router", Key: testWgKeyB, IP: netip.MustParseAddr("100.64.0.2"), DNSLabel: "router"}

	policy := &nmdata.Policy{
		ID: "pol-1", PublicID: "10", Enabled: true,
		Rules: []*nmdata.PolicyRule{{
			ID: "rule-1", PolicyID: "pol-1", Enabled: true,
			Action:       string(types.PolicyTrafficActionAccept),
			Protocol:     string(types.PolicyRuleProtocolALL),
			Sources:      []string{"group-clients"},
			Destinations: []string{"group-resources"},
		}},
	}

	nmd := &networkmap.NetworkMapData{
		Peers: map[string]*nmdata.Peer{client.ID: client, router.ID: router},
		Groups: map[string]*nmdata.Group{
			"group-clients":   {ID: "group-clients", PublicID: "1", Name: "clients", Peers: []string{client.ID}},
			"group-resources": {ID: "group-resources", PublicID: "2", Name: "resources"},
		},
		ValidatedPeers:  map[string]struct{}{client.ID: {}, router.ID: {}},
		Network:         &nmdata.Network{Identifier: "network-1", Serial: 1},
		AccountSettings: &nmdata.AccountSettingsInfo{},
		DNSSettings:     &nmdata.DNSSettings{},
		Policies:        []*nmdata.Policy{policy},
		NetworkResources: []*nmdata.NetworkResource{
			{ID: "res-auto", PublicID: "20", NetworkID: "net-1", Name: "auto", Type: "subnet",
				Prefix: netip.MustParsePrefix("10.0.0.0/16"), Enabled: true},
			{ID: "res-manual", PublicID: "21", NetworkID: "net-1", Name: "manual", Type: "subnet",
				Prefix: netip.MustParsePrefix("10.1.0.0/16"), Enabled: true, SkipAutoApply: true},
		},
		ResourcePolicies: map[string][]*nmdata.Policy{"res-auto": {policy}, "res-manual": {policy}},
		Routers: map[string]map[string]*nmdata.NetworkRouter{
			"net-1": {router.ID: {PublicID: "30", Metric: 100, Enabled: true}},
		},
		NetworkXIDToPublicID: map[string]string{"net-1": "5"},
	}

	components := nmd.GetPeerNetworkMapComponents(client.ID, nmdata.CustomZone{})
	require.NotNil(t, components)

	env := EncodeNetworkMapEnvelope(ComponentsEnvelopeInput{Components: components})
	res, err := networkmap.EnvelopeToNetworkMap(context.Background(), env, client.Key, "netbird.cloud", false)
	require.NoError(t, err)

	skipByNetID := make(map[string]bool)
	for _, r := range res.NetworkMap.GetRoutes() {
		skipByNetID[r.GetNetID()] = r.GetSkipAutoApply()
	}
	require.Contains(t, skipByNetID, "auto", "the client must get a route for the auto applied resource")
	require.Contains(t, skipByNetID, "manual", "the client must get a route for the skip auto apply resource")
	assert.False(t, skipByNetID["auto"], "a resource without the flag is applied automatically")
	assert.True(t, skipByNetID["manual"], "the flag set on the resource must reach the client route")
}
