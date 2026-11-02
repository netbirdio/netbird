package iptables

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

type filterOnlyIface struct{}

func (filterOnlyIface) Name() string { return "wt-fo" }

func (filterOnlyIface) Address() wgaddr.Address { return wgaddr.Address{} }

// The family that only carries the default deny has nothing to route or NAT, so it must not
// need the nat and mangle tables: a host whose ip6tables lacks them still gets the deny.
func TestFilterOnlyFamilyUsesFilterTableOnly(t *testing.T) {
	full := &family{wgIface: filterOnlyIface{}, entries: make(aclEntries), optionalEntries: make(map[chainKey][]entry)}
	only := &family{wgIface: filterOnlyIface{}, entries: make(aclEntries), optionalEntries: make(map[chainKey][]entry), filterOnly: true}

	var fullTables []string
	for _, c := range full.containerChains() {
		fullTables = append(fullTables, c.table)
	}
	assert.Contains(t, fullTables, tableNat, "the full family sets up nat chains")
	assert.Contains(t, fullTables, tableMangle, "the full family sets up mangle chains")

	for _, c := range only.containerChains() {
		assert.Equal(t, tableFilter, c.table, "chain %s of a filter-only family must live in the filter table", c.chain)
	}

	full.seedInitialEntries()
	only.seedInitialEntries()
	full.seedInitialOptionalEntries()
	only.seedInitialOptionalEntries()
	assert.NotEmpty(t, full.entries[mangleForwardKey], "the full family guards the mangle FORWARD chain")
	assert.Empty(t, only.entries[mangleForwardKey], "a filter-only family adds no mangle rules")

	require.NotEmpty(t, only.entries[chainInput], "the deny still seeds the INPUT rules")
	require.NotEmpty(t, only.entries[chainForward], "the deny still seeds the FORWARD rules")
	assert.Contains(t, only.entries[chainInput], ruleSpec{"-i", "wt-fo", "-j", "DROP"}, "INPUT drops what arrives on the interface")
	assert.Contains(t, only.entries[chainForward], ruleSpec{"-i", "wt-fo", "-j", "DROP"}, "FORWARD drops what arrives on the interface")

	// The mark accept sits above the interface DROP in FORWARD, so with it a packet that
	// carries the redirect mark would get past the deny. Only the full family has redirected
	// traffic to let through, and nothing in a filter-only family sets that mark.
	assert.NotEmpty(t, full.optionalEntries[chainForward], "the full family accepts redirected traffic in FORWARD")
	assert.Empty(t, only.optionalEntries[chainForward], "a filter-only family must not accept marked traffic ahead of its DROP")
}
