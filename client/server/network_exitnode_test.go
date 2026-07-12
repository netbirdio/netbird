package server

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/route"
)

func TestExitNodeSelectionHelpers(t *testing.T) {
	routesMap := map[route.NetID][]*route.Route{
		"exitA": {{Network: netip.MustParsePrefix("0.0.0.0/0")}},
		"exitB": {{Network: netip.MustParsePrefix("::/0")}},
		"lan":   {{Network: netip.MustParsePrefix("192.168.0.0/16")}},
	}

	assert.True(t, requestActivatesExitNode([]route.NetID{"exitA"}, routesMap), "v4 default route is an exit node")
	assert.True(t, requestActivatesExitNode([]route.NetID{"exitB"}, routesMap), "v6 default route is an exit node")
	assert.False(t, requestActivatesExitNode([]route.NetID{"lan"}, routesMap), "lan route is not an exit node")
	assert.False(t, requestActivatesExitNode([]route.NetID{"missing"}, routesMap), "unknown id is not an exit node")

	others := otherExitNodeIDs(routesMap, []route.NetID{"exitB"})
	assert.ElementsMatch(t, []route.NetID{"exitA"}, others, "only the other exit node is a sibling; the lan route is ignored")
}
