package dns

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

// T-DNS-U2: a secondary's host config has no catch-all; match domains stay.
func TestSecondaryHostConfig(t *testing.T) {
	in := HostDNSConfig{
		RouteAll: true,
		ServerIP: netip.MustParseAddr("100.80.255.254"),
		Domains: []DomainConfig{
			{Domain: "acme.internal.", MatchOnly: true},
			{Domain: "netbird.selfhosted"},
			{Domain: "."},
		},
	}
	out, dropped := secondaryHostConfig(in)
	assert.True(t, dropped, "catch-all dropped")
	assert.False(t, out.RouteAll, "no adapter NameServer, no \".\" rule, no .local exemption")
	assert.Equal(t, []DomainConfig{{Domain: "acme.internal.", MatchOnly: true}, {Domain: "netbird.selfhosted"}}, out.Domains, "match domains stay")

	_, dropped = secondaryHostConfig(HostDNSConfig{Domains: []DomainConfig{{Domain: "corp.example"}}})
	assert.False(t, dropped, "nothing to drop")
}

func TestIsForeignNRPTKey(t *testing.T) {
	own := "NetBird_acme-"
	for name, want := range map[string]bool{
		"NetBird-Match-0":       true,
		"netbird-exemptlocal":   true,
		"NetBird_work-Match-0":  true,
		"NetBird_acme2-Match-0": true,
		"NetBird_acme-Match-0":  false,
		"NETBIRD_ACME-Match-1":  false,
		"Corp-Rule":             false,
		"{6B6A-0000}":           false,
		"NetBirdish":            false,
	} {
		assert.Equal(t, want, isForeignNRPTKey(name, own), "key %s", name)
	}
	assert.False(t, isForeignNRPTKey("NetBird-Match-0", "NetBird-"), "the default's own key")
}

// SBS-DNS-04: namespaces another installation claims are skipped.
func TestDropClaimedNamespaces(t *testing.T) {
	claimed := map[string]struct{}{".corp.example": {}, ".netbird.selfhosted": {}}
	kept, skipped := dropClaimedNamespaces([]string{".acme.internal", ".Corp.Example", ".netbird.selfhosted"}, claimed)
	assert.Equal(t, []string{".acme.internal"}, kept, "kept")
	assert.Equal(t, []string{".Corp.Example", ".netbird.selfhosted"}, skipped, "skipped")
}
