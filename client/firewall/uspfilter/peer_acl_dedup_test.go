package uspfilter

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	fw "github.com/netbirdio/netbird/client/firewall/manager"
	nbiface "github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/device"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	ifaceMock := &IFaceMock{
		SetFilterFunc: func(device.PacketFilter) error { return nil },
	}
	m, err := Create(Config{IFace: ifaceMock, FlowLogger: flowLogger, MTU: nbiface.DefaultMTU})
	require.NoError(t, err, "create manager")
	t.Cleanup(func() { require.NoError(t, m.Close(nil)) })
	return m
}

// TestAddPeerFiltering_DeduplicatesIdenticalRules verifies that adding
// the same peer rule twice does not create two backing rules. The acl
// manager keys its own cache, but the firewall backend must be
// idempotent on its own so a double-apply cannot leak rules, matching
// the route path and the kernel backends.
func TestAddPeerFiltering_DeduplicatesIdenticalRules(t *testing.T) {
	m := newTestManager(t)

	ip := net.ParseIP("192.168.1.1")
	proto := fw.ProtocolTCP
	port := &fw.Port{Values: []uint16{80}}
	action := fw.ActionDrop

	first, err := m.AddFilterRule(nil, pfx(ip), fw.Network{}, proto, nil, port, action)
	require.NoError(t, err, "first add")

	second, err := m.AddFilterRule(nil, pfx(ip), fw.Network{}, proto, nil, port, action)
	require.NoError(t, err, "second add")

	assert.Equal(t, first.ID(), second.ID(), "duplicate add should return the same rule id")
	assert.Len(t, m.incomingDenyRules, 1, "duplicate add must not create a second backing rule")
}

// TestDeletePeerFiltering_NoRefcountSingleDeleteRemoves locks the
// backend's owner accounting for the same-owner case: a content key
// installed twice by the same owner registers one owner claim, so the
// first DeleteFilterRule removes the rule. Owner counting only kicks
// in for distinct management rule IDs (see the peer owner tests); the
// acl manager keys its tracking per (policy, content) and deletes once
// per key, so adds and deletes stay balanced.
func TestDeletePeerFiltering_NoRefcountSingleDeleteRemoves(t *testing.T) {
	m := newTestManager(t)

	ip := net.ParseIP("192.168.1.1")
	proto := fw.ProtocolTCP
	port := &fw.Port{Values: []uint16{80}}
	action := fw.ActionDrop

	first, err := m.AddFilterRule(nil, pfx(ip), fw.Network{}, proto, nil, port, action)
	require.NoError(t, err, "first add")

	second, err := m.AddFilterRule(nil, pfx(ip), fw.Network{}, proto, nil, port, action)
	require.NoError(t, err, "second add")
	require.Equal(t, first.ID(), second.ID(), "dedup to one rule")
	require.Len(t, m.incomingDenyRules, 1, "still one backing rule after duplicate add")

	require.NoError(t, m.DeleteFilterRule(first), "delete once")
	assert.Empty(t, m.incomingDenyRules, "single delete removes the backing rule (no refcount)")
	assert.NotContains(t, m.peerRulesMap, first.ID(), "dedup map entry cleared")
}

// TestAddPeerFiltering_DeterministicID verifies the peer rule id is a
// content hash, not a random UUID: identical inputs produce the same id
// across independent managers. A random id breaks caller-side dedup.
func TestAddPeerFiltering_DeterministicID(t *testing.T) {
	ip := net.ParseIP("10.0.0.5")
	proto := fw.ProtocolUDP
	port := &fw.Port{Values: []uint16{53}}
	action := fw.ActionAccept

	m1 := newTestManager(t)
	r1, err := m1.AddFilterRule(nil, pfx(ip), fw.Network{}, proto, nil, port, action)
	require.NoError(t, err)

	m2 := newTestManager(t)
	r2, err := m2.AddFilterRule(nil, pfx(ip), fw.Network{}, proto, nil, port, action)
	require.NoError(t, err)

	assert.Equal(t, r1.ID(), r2.ID(), "same inputs must produce the same rule id")
}

// TestAddPeerFiltering_DistinctRulesNotDeduped verifies that rules
// differing only by port are kept separate.
func TestAddPeerFiltering_DistinctRulesNotDeduped(t *testing.T) {
	m := newTestManager(t)

	ip := net.ParseIP("192.168.1.1")
	proto := fw.ProtocolTCP
	action := fw.ActionAccept

	r80, err := m.AddFilterRule(nil, pfx(ip), fw.Network{}, proto, nil, &fw.Port{Values: []uint16{80}}, action)
	require.NoError(t, err)

	r443, err := m.AddFilterRule(nil, pfx(ip), fw.Network{}, proto, nil, &fw.Port{Values: []uint16{443}}, action)
	require.NoError(t, err)

	assert.NotEqual(t, r80.ID(), r443.ID(), "different ports must produce different rule ids")
	assert.Len(t, m.incomingAcceptRules, 2, "distinct rules must both be stored")
}

// TestAddPeerFiltering_SourceVsDestPortNotDeduped verifies that a rule
// matching on source port and one matching on destination port for the
// same selector do not collide: the port lands in a different slot, so
// the content key must differ.
func TestAddPeerFiltering_SourceVsDestPortNotDeduped(t *testing.T) {
	m := newTestManager(t)

	ip := net.ParseIP("192.168.1.1")
	proto := fw.ProtocolTCP
	port := &fw.Port{Values: []uint16{80}}
	action := fw.ActionAccept

	dPortRule, err := m.AddFilterRule(nil, pfx(ip), fw.Network{}, proto, nil, port, action)
	require.NoError(t, err)

	sPortRule, err := m.AddFilterRule(nil, pfx(ip), fw.Network{}, proto, port, nil, action)
	require.NoError(t, err)

	assert.NotEqual(t, dPortRule.ID(), sPortRule.ID(), "source-port and dest-port matches must produce different rule ids")
}

// TestAddFilterRule_EmptySourcesRejected verifies that an empty source
// list is rejected rather than treated as "match any". "Match any" must
// be an explicit /0, so a zeroed list can never silently widen a rule to
// every source.
func TestAddFilterRule_EmptySourcesRejected(t *testing.T) {
	m := newTestManager(t)

	proto := fw.ProtocolTCP
	port := &fw.Port{Values: []uint16{80}}

	_, err := m.AddFilterRule(nil, nil, fw.Network{}, proto, nil, port, fw.ActionAccept)
	require.ErrorIs(t, err, fw.ErrNoSources, "empty sources must be rejected")
	assert.Empty(t, m.incomingAcceptRules, "no rule should be stored for empty sources")
}
