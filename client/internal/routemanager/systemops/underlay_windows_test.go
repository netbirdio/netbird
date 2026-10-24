package systemops

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/client/internal/routemanager/vars"
)

// With an exit node the NetBird interface carries 0/1 and 128/1, which win the
// lookup unless that interface is skipped. When it cannot be resolved the
// underlay is unknown: the lookup must fail, not return the tunnel or claim
// there is no default.
func TestGetUnderlayNextHopFailsWhenTheVPNInterfaceIsUnknown(t *testing.T) {
	_, err := GetUnderlayNextHop(netip.IPv4Unspecified(), "nb-test-missing0")
	assert.Error(t, err, "an unresolvable NetBird interface fails the lookup")
	assert.NotErrorIs(t, err, vars.ErrRouteNotFound, "and is not mistaken for a missing default")
}
