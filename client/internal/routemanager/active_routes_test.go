package routemanager

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/routeselector"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/domain"
)

// Recorder keys are spelled out here instead of being taken from NetString():
// deriving them would pass even if reader and writer agreed on a key the
// recorder never uses.
func TestGetActiveClientRoutes(t *testing.T) {
	const peerKey = "peerA"

	// Network is the placeholder management sends for domain routes.
	domainRoute := &route.Route{
		ID:          "r1",
		NetID:       "corp-domains",
		Peer:        peerKey,
		Network:     netip.MustParsePrefix("192.0.2.0/32"),
		Domains:     domain.List{"gitlab.example.com"},
		NetworkType: route.DomainNetwork,
		Enabled:     true,
	}
	staticRoute := &route.Route{
		ID:          "r2",
		NetID:       "corp-net",
		Peer:        peerKey,
		Network:     netip.MustParsePrefix("10.0.0.0/24"),
		NetworkType: route.IPv4Network,
		Enabled:     true,
	}

	tests := []struct {
		name string
		rt   *route.Route
		// key the status recorder holds for the peer, empty for none
		recordedKey string
		status      peer.ConnStatus
		wantActive  bool
	}{
		{"domain route, connected peer, route recorded", domainRoute, "gitlab.example.com", peer.StatusConnected, true},
		{"domain route, connected peer, no route recorded", domainRoute, "", peer.StatusConnected, false},
		{"domain route, route recorded, peer not connected", domainRoute, "gitlab.example.com", peer.StatusIdle, false},
		{"static route, connected peer, route recorded", staticRoute, "10.0.0.0/24", peer.StatusConnected, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			recorder := peer.NewRecorder("https://mgm")
			require.NoError(t, recorder.AddPeer(peerKey, "vpn-me.netbird.cloud", "100.64.0.1", ""))
			require.NoError(t, recorder.UpdatePeerState(peer.State{
				PubKey:     peerKey,
				ConnStatus: tc.status,
			}))
			if tc.recordedKey != "" {
				require.NoError(t, recorder.AddPeerStateRoute(peerKey, tc.recordedKey, route.ResID("res1")))
			}

			mgr := &DefaultManager{
				clientRoutes:   route.HAMap{tc.rt.GetHAUniqueID(): []*route.Route{tc.rt}},
				statusRecorder: recorder,
				routeSelector:  routeselector.NewRouteSelector(),
			}

			active := mgr.GetActiveClientRoutes()
			if tc.wantActive {
				require.Contains(t, active, tc.rt.GetHAUniqueID())
				return
			}
			require.NotContains(t, active, tc.rt.GetHAUniqueID())
		})
	}
}
