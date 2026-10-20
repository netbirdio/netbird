package server

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/route"
)

// routingFirewall records the routing lifecycle calls the router makes. The
// embedded interface covers the methods this test never reaches.
type routingFirewall struct {
	firewall.Manager

	removed  []firewall.RouterPair
	enabled  int
	disabled int
}

func (f *routingFirewall) RemoveNatRule(pair firewall.RouterPair) error {
	f.removed = append(f.removed, pair)
	return nil
}

func (f *routingFirewall) EnableRouting() error {
	f.enabled++
	return nil
}

func (f *routingFirewall) DisableRouting() error {
	f.disabled++
	return nil
}

// TestRouterCleanUpReleasesRouting covers the shutdown path: the router holds a
// routing reference for as long as it serves routes, and CleanUp has to give it
// back. Without that the sysctls the reference enabled (IPv6 forwarding and the
// accept_ra values that keep RA handling working alongside it) stay applied
// after the client stops, leaving the host configured as a router.
func TestRouterCleanUpReleasesRouting(t *testing.T) {
	fw := &routingFirewall{}
	r := &Router{
		ctx:            context.Background(),
		firewall:       fw,
		statusRecorder: peer.NewRecorder("https://mgm"),
		routes: map[route.ID]*route.Route{
			"route-1": {
				ID:          "route-1",
				Network:     netip.MustParsePrefix("192.168.55.0/24"),
				NetworkType: route.IPv4Network,
				Masquerade:  true,
			},
		},
	}

	r.CleanUp()

	require.Len(t, fw.removed, 1, "the route's NAT rule must be removed")
	assert.Equal(t, 1, fw.disabled, "CleanUp must release the routing reference")
}
