package acl

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	fwmgr "github.com/netbirdio/netbird/client/firewall/manager"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

var (
	countryUSv4 = netip.MustParsePrefix("8.8.8.0/24")
	countryUSv6 = netip.MustParsePrefix("2001:4860::/32")
)

// countryRouteRules mirrors what management sends a routing peer for a country route with
// dual-stack sources: one rule per address family, both naming the same countries.
func countryRouteRules() []*mgmProto.RouteFirewallRule {
	rule := func(source string) *mgmProto.RouteFirewallRule {
		return &mgmProto.RouteFirewallRule{
			SourceRanges: []string{source},
			Action:       mgmProto.RuleAction_ACCEPT,
			Protocol:     mgmProto.RuleProtocol_ALL,
			Destination:  "192.0.2.0/32",
			Countries:    []string{"US"},
			RouteID:      "route-us",
			PolicyID:     []byte("policy-1"),
		}
	}
	return []*mgmProto.RouteFirewallRule{rule("100.64.0.2/32"), rule("fd00::2/128")}
}

func TestCountryRouteRulesFillTheirSet(t *testing.T) {
	acl, fw, cleanup := newCountingACL(t)
	defer cleanup()

	fetches := 0
	acl.SetCountryPrefixes(func(_ context.Context, country string) ([]netip.Prefix, error) {
		fetches++
		require.Equal(t, "US", country)
		return []netip.Prefix{countryUSv4, countryUSv6}, nil
	})

	require.NoError(t, acl.applyRouteACLs(countryRouteRules(), true))

	assert.Equal(t, 2, fw.distinctRules(), "each address family should get its own rule")
	assert.Equal(t, 1, fetches, "the rules of one route should share a single fetch")
	set := fwmgr.NewCountrySet([]string{"US"})
	require.Len(t, fw.setUpdates, 2, "each new rule should fill the set for its family")
	assert.Equal(t, setUpdate{set: set, prefixes: []netip.Prefix{countryUSv4}}, fw.setUpdates[0],
		"the v4 rule should load only v4 prefixes")
	assert.Equal(t, setUpdate{set: set, prefixes: []netip.Prefix{countryUSv6}}, fw.setUpdates[1],
		"the v6 rule should load only v6 prefixes")

	// The rules already exist and their sets are filled, so nothing is fetched or loaded again.
	require.NoError(t, acl.applyRouteACLs(countryRouteRules(), true))
	assert.Equal(t, 1, fetches, "unchanged rules must not fetch again")
	assert.Len(t, fw.setUpdates, 2, "unchanged rules must not reload their set")
}

func TestCountryRouteRuleRetriesFailedFetch(t *testing.T) {
	acl, fw, cleanup := newCountingACL(t)
	defer cleanup()

	fail := true
	acl.SetCountryPrefixes(func(context.Context, string) ([]netip.Prefix, error) {
		if fail {
			return nil, errors.New("management unreachable")
		}
		return []netip.Prefix{countryUSv4, countryUSv6}, nil
	})

	rules := countryRouteRules()[:1]
	require.Error(t, acl.applyRouteACLs(rules, true))
	assert.Equal(t, 0, fw.distinctRules(), "a rule whose set cannot be filled must not be kept")
	assert.Empty(t, fw.setUpdates)

	fail = false
	require.NoError(t, acl.applyRouteACLs(rules, true))
	assert.Equal(t, 1, fw.distinctRules(), "the next update should create the rule again")
	require.Len(t, fw.setUpdates, 1, "and fill its set")
	assert.Equal(t, []netip.Prefix{countryUSv4}, fw.setUpdates[0].prefixes)
}
