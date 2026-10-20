package notifier

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/route"
)

func routeFor(id route.ID, prefix string) *route.Route {
	return &route.Route{
		ID:      id,
		NetID:   "net",
		Network: netip.MustParsePrefix(prefix),
	}
}

// TestHasRouteDiff_IgnoresHACandidateCount is the reason the comparison
// deduplicates. Every notification renews the TUN, and a renewed TUN
// invalidates the sockets the embedded servers are listening on, so a peer
// joining or leaving an HA group must not count as a route change when the
// prefixes the TUN carries are identical.
func TestHasRouteDiff_IgnoresHACandidateCount(t *testing.T) {
	onePeer := []*route.Route{routeFor("a", "10.0.0.0/24")}
	twoPeers := []*route.Route{
		routeFor("a", "10.0.0.0/24"),
		routeFor("b", "10.0.0.0/24"),
	}

	assert.False(t, hasRouteDiff(onePeer, twoPeers),
		"a second peer serving the same prefix is not a route change")
	assert.False(t, hasRouteDiff(twoPeers, onePeer),
		"losing one of two peers serving the same prefix is not a route change")
}

func TestHasRouteDiff_ReportsRealChanges(t *testing.T) {
	tests := []struct {
		name string
		a    []*route.Route
		b    []*route.Route
		want bool
	}{
		{
			name: "added prefix",
			a:    []*route.Route{routeFor("a", "10.0.0.0/24")},
			b:    []*route.Route{routeFor("a", "10.0.0.0/24"), routeFor("b", "10.0.1.0/24")},
			want: true,
		},
		{
			name: "removed prefix",
			a:    []*route.Route{routeFor("a", "10.0.0.0/24"), routeFor("b", "10.0.1.0/24")},
			b:    []*route.Route{routeFor("a", "10.0.0.0/24")},
			want: true,
		},
		{
			name: "replaced prefix",
			a:    []*route.Route{routeFor("a", "10.0.0.0/24")},
			b:    []*route.Route{routeFor("a", "10.0.1.0/24")},
			want: true,
		},
		{
			name: "same prefix, different order",
			a:    []*route.Route{routeFor("a", "10.0.1.0/24"), routeFor("b", "10.0.0.0/24")},
			b:    []*route.Route{routeFor("b", "10.0.0.0/24"), routeFor("a", "10.0.1.0/24")},
			want: false,
		},
		{
			name: "all routes gone",
			a:    []*route.Route{routeFor("a", "10.0.0.0/24")},
			b:    nil,
			want: true,
		},
		{
			name: "both empty",
			a:    nil,
			b:    nil,
			want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, hasRouteDiff(tc.a, tc.b),
				"route diff for %s", tc.name)
		})
	}
}
