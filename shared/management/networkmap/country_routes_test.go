package networkmap_test

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	goproto "google.golang.org/protobuf/proto"

	mgmtgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"
	"github.com/netbirdio/netbird/management/server/types"
	nbnetworkmap "github.com/netbirdio/netbird/shared/management/networkmap"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// TestEnvelopeToNetworkMap_CountryRoutes runs a country route through the client-side
// pipeline: encode on management, decode and Calculate on the peer. The route only
// reaches a peer when both that peer and the routing peer support country routes.
func TestEnvelopeToNetworkMap_CountryRoutes(t *testing.T) {
	tests := []struct {
		name           string
		sourceCapable  bool
		exitCapable    bool
		expectRoute    bool
		expectRuleOnRP bool
	}{
		{name: "both peers support country routes", sourceCapable: true, exitCapable: true, expectRoute: true, expectRuleOnRP: true},
		{name: "source peer without support", sourceCapable: false, exitCapable: true, expectRoute: false, expectRuleOnRP: true},
		{name: "routing peer without support", sourceCapable: true, exitCapable: false, expectRoute: false, expectRuleOnRP: false},
	}

	aclModes := []struct {
		name                string
		accessControlGroups []string
		source              string
	}{
		// Without access control groups the routing peer permits every source.
		{name: "default permit", source: "0.0.0.0/0"},
		// With one, the ACL comes from the policies whose destinations hold the group, and its
		// sources are the policy's sources in the distribution group: the source peer only.
		{name: "policy", accessControlGroups: []string{"g-all"}, source: "100.64.0.1/32"},
	}

	for _, mode := range aclModes {
		for _, tt := range tests {
			t.Run(mode.name+"/"+tt.name, func(t *testing.T) {
				c, sourceKey, exitKey := buildCountryRouteComponents(t, "peer-S", tt.sourceCapable, tt.exitCapable, mode.accessControlGroups)
				sourceMap := countryRouteNetworkMap(t, c, sourceKey)
				countryRoutes := filterCountryRoutes(sourceMap.Routes)
				if !tt.expectRoute {
					assert.Empty(t, countryRoutes, "the source peer must not receive the country route")
				} else {
					require.Len(t, countryRoutes, 1, "the source peer should receive the country route")
					assert.Equal(t, []string{"US", "CA"}, countryRoutes[0].Countries, "countries should survive the envelope")
					assert.Equal(t, exitKey, countryRoutes[0].Peer, "the route should point at the exit node")
					assert.Equal(t, "us-exit", countryRoutes[0].NetID)
				}

				c, _, exitKey = buildCountryRouteComponents(t, "peer-E", tt.sourceCapable, tt.exitCapable, mode.accessControlGroups)
				exitMap := countryRouteNetworkMap(t, c, exitKey)
				var countryRules []*proto.RouteFirewallRule
				for _, rule := range exitMap.RoutesFirewallRules {
					if len(rule.Countries) > 0 {
						countryRules = append(countryRules, rule)
					}
				}
				if !tt.expectRuleOnRP {
					assert.Empty(t, countryRules, "a routing peer without support must not get country rules")
					assert.Empty(t, filterCountryRoutes(exitMap.Routes), "a routing peer without support must not serve the route")
					return
				}
				require.NotEmpty(t, countryRules, "the routing peer should get the country route ACL")
				var sources []string
				for _, rule := range countryRules {
					assert.Equal(t, []string{"US", "CA"}, rule.Countries, "the rule should carry the countries")
					sources = append(sources, rule.SourceRanges...)
				}
				assert.Equal(t, []string{mode.source}, sources, "the country ACL sources should come from the %s path", mode.name)
			})
		}
	}
}

func countryRouteNetworkMap(t *testing.T, c *types.NetworkMapComponents, peerKey string) *proto.NetworkMap {
	t.Helper()

	envelope := mgmtgrpc.EncodeNetworkMapEnvelope(mgmtgrpc.ComponentsEnvelopeInput{
		Components: c,
		DNSDomain:  "netbird.cloud",
	})
	wire, err := goproto.Marshal(envelope)
	require.NoError(t, err, "marshal envelope")
	var decoded proto.NetworkMapEnvelope
	require.NoError(t, goproto.Unmarshal(wire, &decoded), "unmarshal envelope")

	result, err := nbnetworkmap.EnvelopeToNetworkMap(context.Background(), &decoded, peerKey, "netbird.cloud", false)
	require.NoError(t, err, "EnvelopeToNetworkMap")
	require.NotNil(t, result.NetworkMap)
	return result.NetworkMap
}

func filterCountryRoutes(routes []*proto.Route) []*proto.Route {
	var out []*proto.Route
	for _, r := range routes {
		if r.NetworkType == nmdata.NetworkTypeCountry {
			out = append(out, r)
		}
	}
	return out
}

// buildCountryRouteComponents returns components, seen from localPeerID, with a source peer S
// and an exit peer E that routes US and CA traffic for the sources group.
func buildCountryRouteComponents(t *testing.T, localPeerID string, sourceCapable, exitCapable bool, accessControlGroups []string) (*types.NetworkMapComponents, string, string) {
	t.Helper()

	capabilities := func(capable bool) []int32 {
		if capable {
			return []int32{nmdata.PeerCapabilityCountryRoutes}
		}
		return nil
	}

	sourceKey := randomWgKey(t)
	exitKey := randomWgKey(t)
	peers := map[string]*nmdata.Peer{
		"peer-S": {
			ID: "peer-S", Key: sourceKey, DNSLabel: "source",
			IP:   netip.AddrFrom4([4]byte{100, 64, 0, 1}),
			Meta: nmdata.PeerSystemMeta{WtVersion: "0.40.0", Capabilities: capabilities(sourceCapable)},
		},
		"peer-E": {
			ID: "peer-E", Key: exitKey, DNSLabel: "exit",
			IP:   netip.AddrFrom4([4]byte{100, 64, 0, 2}),
			Meta: nmdata.PeerSystemMeta{WtVersion: "0.40.0", Capabilities: capabilities(exitCapable)},
		},
	}

	policy := &nmdata.Policy{
		ID: "pol-allow", PublicID: "1", Enabled: true,
		Rules: []*nmdata.PolicyRule{{
			ID:            "rule-allow",
			Enabled:       true,
			Action:        string(types.PolicyTrafficActionAccept),
			Protocol:      string(types.PolicyRuleProtocolALL),
			Bidirectional: true,
			Sources:       []string{"g-all"},
			Destinations:  []string{"g-all"},
		}},
	}

	c := &types.NetworkMapComponents{
		PeerID: localPeerID,
		Network: &nmdata.Network{
			Identifier: "net-country",
			Net:        net.IPNet{IP: net.IP{100, 64, 0, 0}, Mask: net.CIDRMask(10, 32)},
			Serial:     1,
		},
		AccountSettings: &nmdata.AccountSettingsInfo{},
		DNSSettings:     &nmdata.DNSSettings{},
		Peers:           peers,
		Groups: map[string]*nmdata.Group{
			"g-all":     {PublicID: "1", Name: "All", Peers: []string{"peer-S", "peer-E"}},
			"g-sources": {PublicID: "2", Name: "sources", Peers: []string{"peer-S"}},
		},
		Policies: []*nmdata.Policy{policy},
		Routes: []*nmdata.Route{{
			ID:                  "route-us",
			PublicID:            "100",
			NetID:               "us-exit",
			Network:             netip.MustParsePrefix("192.0.2.0/32"),
			Countries:           []string{"US", "CA"},
			NetworkType:         nmdata.NetworkTypeCountry,
			Peer:                "peer-E",
			Groups:              []string{"g-sources"},
			AccessControlGroups: accessControlGroups,
			Masquerade:          true,
			Metric:              9999,
			Enabled:             true,
		}},
	}
	return c, sourceKey, exitKey
}
