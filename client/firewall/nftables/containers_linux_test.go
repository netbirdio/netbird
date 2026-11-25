//go:build !android

package nftables

import (
	"testing"

	"github.com/google/nftables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A family that only carries the IPv6 default deny must not need NAT or mangle chains: a kernel
// can filter IPv6 without supporting them, and creating one would fail the whole table.
func TestContainerChainsDenyOnlyHasNoNATOrMangle(t *testing.T) {
	table := &nftables.Table{Name: "test", Family: nftables.TableFamilyIPv6}

	denyOnly := (&family{workTable: table, denyOnly: true}).containerChains()
	require.Len(t, denyOnly, 1, "deny-only family creates only the routing chain")
	assert.Equal(t, chainNameRoutingFw, denyOnly[0].Name)
	assert.Nil(t, denyOnly[0].Hooknum, "the routing chain is a plain chain the forward filter jumps to")

	full := (&family{workTable: table}).containerChains()
	names := make(map[string]nftables.ChainType)
	for _, c := range full {
		names[c.Name] = c.Type
	}
	assert.Equal(t, nftables.ChainTypeNAT, names[chainNameRoutingNat], "a routing family keeps its NAT chains")
	assert.Contains(t, names, chainNameManglePrerouting, "a routing family keeps its mangle chains")
}
