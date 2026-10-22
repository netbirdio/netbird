package route

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExpandV6ExitPairs(t *testing.T) {
	v4ExitRoute := &Route{Network: netip.MustParsePrefix("0.0.0.0/0")}
	v6ExitRoute := &Route{Network: netip.MustParsePrefix("::/0")}
	regularRoute := &Route{Network: netip.MustParsePrefix("10.0.0.0/8")}

	tests := []struct {
		name      string
		ids       []NetID
		routesMap map[NetID][]*Route
		expected  []NetID
	}{
		{
			name: "v4 exit node with matching v6 pair",
			ids:  []NetID{"exit-node"},
			routesMap: map[NetID][]*Route{
				"exit-node":    {v4ExitRoute},
				"exit-node-v6": {v6ExitRoute},
			},
			expected: []NetID{"exit-node", "exit-node-v6"},
		},
		{
			name: "v4 exit node without v6 pair",
			ids:  []NetID{"exit-node"},
			routesMap: map[NetID][]*Route{
				"exit-node": {v4ExitRoute},
			},
			expected: []NetID{"exit-node"},
		},
		{
			name: "regular route is not expanded",
			ids:  []NetID{"office"},
			routesMap: map[NetID][]*Route{
				"office":    {regularRoute},
				"office-v6": {v6ExitRoute},
			},
			expected: []NetID{"office"},
		},
		{
			name: "v6 already included is not duplicated",
			ids:  []NetID{"exit-node", "exit-node-v6"},
			routesMap: map[NetID][]*Route{
				"exit-node":    {v4ExitRoute},
				"exit-node-v6": {v6ExitRoute},
			},
			expected: []NetID{"exit-node", "exit-node-v6"},
		},
		{
			name: "multiple exit nodes expanded independently",
			ids:  []NetID{"exit-a", "exit-b"},
			routesMap: map[NetID][]*Route{
				"exit-a":    {v4ExitRoute},
				"exit-a-v6": {v6ExitRoute},
				"exit-b":    {v4ExitRoute},
				"exit-b-v6": {v6ExitRoute},
			},
			expected: []NetID{"exit-a", "exit-b", "exit-a-v6", "exit-b-v6"},
		},
		{
			name: "v6 suffix but not exit node network",
			ids:  []NetID{"office"},
			routesMap: map[NetID][]*Route{
				"office":    {regularRoute},
				"office-v6": {regularRoute},
			},
			expected: []NetID{"office"},
		},
		{
			name: "user-chosen name for exit node with v6 pair",
			ids:  []NetID{"my-exit"},
			routesMap: map[NetID][]*Route{
				"my-exit":    {v4ExitRoute},
				"my-exit-v6": {v6ExitRoute},
			},
			expected: []NetID{"my-exit", "my-exit-v6"},
		},
		{
			name: "real-world management-generated IDs",
			ids:  []NetID{"0.0.0.0/0"},
			routesMap: map[NetID][]*Route{
				"0.0.0.0/0":    {v4ExitRoute},
				"0.0.0.0/0-v6": {v6ExitRoute},
			},
			expected: []NetID{"0.0.0.0/0", "0.0.0.0/0-v6"},
		},
		{
			name:      "empty input",
			ids:       []NetID{},
			routesMap: map[NetID][]*Route{},
			expected:  []NetID{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExpandV6ExitPairs(tt.ids, tt.routesMap)
			assert.ElementsMatch(t, tt.expected, result)
		})
	}
}

func TestCountryRoute(t *testing.T) {
	r := &Route{
		ID:          "r1",
		NetID:       "us-exit",
		Network:     netip.MustParsePrefix("192.0.2.0/32"),
		NetworkType: CountryNetwork,
		Countries:   []string{"US", "CA"},
	}

	assert.True(t, r.IsCountry(), "a country network type is a country route")
	assert.False(t, r.IsDynamic(), "a country route is not a DNS route")
	assert.Equal(t, "US, CA", r.NetString(), "NetString should list the countries, not the placeholder")
	assert.Equal(t, HAUniqueID("us-exit|US, CA"), r.GetHAUniqueID())
	assert.Equal(t, CountryNetwork, ToPrefixType(r.NetworkType.String()), "the type should survive its string form")

	copied := r.Copy()
	assert.True(t, r.Equal(copied), "a copy should equal the original")
	copied.Countries[0] = "DE"
	assert.Equal(t, "US", r.Countries[0], "the copy must not share the countries slice")
	assert.False(t, r.Equal(copied), "routes with different countries are not equal")
}
