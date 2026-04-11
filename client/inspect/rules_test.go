package inspect

import (
	"net/netip"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/acl/id"
	"github.com/netbirdio/netbird/shared/management/domain"
)

func testLogger() *log.Entry {
	return log.WithField("test", true)
}

func mustDomain(t *testing.T, s string) domain.Domain {
	t.Helper()
	d, err := domain.FromString(s)
	require.NoError(t, err)
	return d
}

func TestRuleEngine_Evaluate(t *testing.T) {
	tests := []struct {
		name          string
		rules         []Rule
		defaultAction Action
		src           netip.Addr
		dstDomain     domain.Domain
		dstAddr       netip.Addr
		dstPort       uint16
		want          Action
	}{
		{
			name:          "no rules returns default allow",
			defaultAction: ActionAllow,
			src:           netip.MustParseAddr("10.0.0.1"),
			dstAddr:       netip.MustParseAddr("1.2.3.4"),
			dstPort:       443,
			want:          ActionAllow,
		},
		{
			name:          "no rules returns default block",
			defaultAction: ActionBlock,
			src:           netip.MustParseAddr("10.0.0.1"),
			dstAddr:       netip.MustParseAddr("1.2.3.4"),
			dstPort:       443,
			want:          ActionBlock,
		},
		{
			name:          "domain exact match blocks",
			defaultAction: ActionAllow,
			rules: []Rule{
				{
					ID:      id.RuleID("r1"),
					Domains: []domain.Domain{mustDomain(t, "malware.example.com")},
					Action:  ActionBlock,
				},
			},
			src:       netip.MustParseAddr("10.0.0.1"),
			dstDomain: mustDomain(t, "malware.example.com"),
			dstAddr:   netip.MustParseAddr("1.2.3.4"),
			dstPort:   443,
			want:      ActionBlock,
		},
		{
			name:          "domain wildcard match blocks",
			defaultAction: ActionAllow,
			rules: []Rule{
				{
					ID:      id.RuleID("r1"),
					Domains: []domain.Domain{mustDomain(t, "*.evil.com")},
					Action:  ActionBlock,
				},
			},
			src:       netip.MustParseAddr("10.0.0.1"),
			dstDomain: mustDomain(t, "phishing.evil.com"),
			dstAddr:   netip.MustParseAddr("1.2.3.4"),
			dstPort:   443,
			want:      ActionBlock,
		},
		{
			name:          "domain wildcard does not match base",
			defaultAction: ActionAllow,
			rules: []Rule{
				{
					ID:      id.RuleID("r1"),
					Domains: []domain.Domain{mustDomain(t, "*.evil.com")},
					Action:  ActionBlock,
				},
			},
			src:       netip.MustParseAddr("10.0.0.1"),
			dstDomain: mustDomain(t, "evil.com"),
			dstAddr:   netip.MustParseAddr("1.2.3.4"),
			dstPort:   443,
			want:      ActionAllow,
		},
		{
			name:          "case insensitive domain match",
			defaultAction: ActionAllow,
			rules: []Rule{
				{
					ID:      id.RuleID("r1"),
					Domains: []domain.Domain{mustDomain(t, "Example.COM")},
					Action:  ActionBlock,
				},
			},
			src:       netip.MustParseAddr("10.0.0.1"),
			dstDomain: mustDomain(t, "EXAMPLE.com"),
			dstAddr:   netip.MustParseAddr("1.2.3.4"),
			dstPort:   443,
			want:      ActionBlock,
		},
		{
			name:          "source CIDR match",
			defaultAction: ActionAllow,
			rules: []Rule{
				{
					ID:      id.RuleID("r1"),
					Sources: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
					Action:  ActionInspect,
				},
			},
			src:     netip.MustParseAddr("192.168.1.50"),
			dstAddr: netip.MustParseAddr("1.2.3.4"),
			dstPort: 443,
			want:    ActionInspect,
		},
		{
			name:          "source CIDR no match",
			defaultAction: ActionAllow,
			rules: []Rule{
				{
					ID:      id.RuleID("r1"),
					Sources: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
					Action:  ActionBlock,
				},
			},
			src:     netip.MustParseAddr("10.0.0.5"),
			dstAddr: netip.MustParseAddr("1.2.3.4"),
			dstPort: 443,
			want:    ActionAllow,
		},
		{
			name:          "destination network match",
			defaultAction: ActionAllow,
			rules: []Rule{
				{
					ID:       id.RuleID("r1"),
					Networks: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
					Action:   ActionInspect,
				},
			},
			src:     netip.MustParseAddr("192.168.1.1"),
			dstAddr: netip.MustParseAddr("10.50.0.1"),
			dstPort: 80,
			want:    ActionInspect,
		},
		{
			name:          "port match",
			defaultAction: ActionAllow,
			rules: []Rule{
				{
					ID:     id.RuleID("r1"),
					Ports:  []uint16{443, 8443},
					Action: ActionInspect,
				},
			},
			src:     netip.MustParseAddr("10.0.0.1"),
			dstAddr: netip.MustParseAddr("1.2.3.4"),
			dstPort: 443,
			want:    ActionInspect,
		},
		{
			name:          "port no match",
			defaultAction: ActionAllow,
			rules: []Rule{
				{
					ID:     id.RuleID("r1"),
					Ports:  []uint16{443, 8443},
					Action: ActionBlock,
				},
			},
			src:     netip.MustParseAddr("10.0.0.1"),
			dstAddr: netip.MustParseAddr("1.2.3.4"),
			dstPort: 22,
			want:    ActionAllow,
		},
		{
			name:          "priority ordering first match wins",
			defaultAction: ActionAllow,
			rules: []Rule{
				{
					ID:       id.RuleID("allow-internal"),
					Domains:  []domain.Domain{mustDomain(t, "*.internal.corp")},
					Action:   ActionAllow,
					Priority: 1,
				},
				{
					ID:       id.RuleID("inspect-all"),
					Action:   ActionInspect,
					Priority: 10,
				},
			},
			src:       netip.MustParseAddr("10.0.0.1"),
			dstDomain: mustDomain(t, "api.internal.corp"),
			dstAddr:   netip.MustParseAddr("10.1.0.5"),
			dstPort:   443,
			want:      ActionAllow,
		},
		{
			name:          "all fields must match (AND logic)",
			defaultAction: ActionAllow,
			rules: []Rule{
				{
					ID:      id.RuleID("r1"),
					Sources: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
					Domains: []domain.Domain{mustDomain(t, "*.evil.com")},
					Ports:   []uint16{443},
					Action:  ActionBlock,
				},
			},
			// Source matches, domain matches, but port doesn't
			src:       netip.MustParseAddr("192.168.1.10"),
			dstDomain: mustDomain(t, "phish.evil.com"),
			dstAddr:   netip.MustParseAddr("1.2.3.4"),
			dstPort:   8080,
			want:      ActionAllow,
		},
		{
			name:          "empty domain with domain rule does not match",
			defaultAction: ActionAllow,
			rules: []Rule{
				{
					ID:      id.RuleID("r1"),
					Domains: []domain.Domain{mustDomain(t, "example.com")},
					Action:  ActionBlock,
				},
			},
			src:       netip.MustParseAddr("10.0.0.1"),
			dstDomain: "", // raw IP connection, no SNI
			dstAddr:   netip.MustParseAddr("1.2.3.4"),
			dstPort:   443,
			want:      ActionAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := NewRuleEngine(testLogger(), tt.defaultAction)
			engine.UpdateRules(tt.rules, tt.defaultAction)

			got := engine.Evaluate(tt.src, tt.dstDomain, tt.dstAddr, tt.dstPort, "", "")
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRuleEngine_ProtocolMatching(t *testing.T) {
	engine := NewRuleEngine(testLogger(), ActionAllow)
	engine.UpdateRules([]Rule{
		{
			ID:        "block-websocket",
			Protocols: []ProtoType{ProtoWebSocket},
			Action:    ActionBlock,
			Priority:  1,
		},
		{
			ID:        "inspect-h2",
			Protocols: []ProtoType{ProtoH2},
			Action:    ActionInspect,
			Priority:  2,
		},
	}, ActionAllow)

	src := netip.MustParseAddr("10.0.0.1")
	dst := netip.MustParseAddr("1.2.3.4")

	// WebSocket: blocked by rule
	assert.Equal(t, ActionBlock, engine.Evaluate(src, "", dst, 443, ProtoWebSocket, ""))

	// HTTP/2: inspected by rule
	assert.Equal(t, ActionInspect, engine.Evaluate(src, "", dst, 443, ProtoH2, ""))

	// Plain HTTP: no protocol rule matches, default allow
	assert.Equal(t, ActionAllow, engine.Evaluate(src, "", dst, 80, ProtoHTTP, ""))

	// HTTPS: no protocol rule matches, default allow
	assert.Equal(t, ActionAllow, engine.Evaluate(src, "", dst, 443, ProtoHTTPS, ""))

	// QUIC/H3: no protocol rule matches, default allow
	assert.Equal(t, ActionAllow, engine.Evaluate(src, "", dst, 443, ProtoH3, ""))

	// Empty protocol (unknown): no protocol rule matches, default allow
	assert.Equal(t, ActionAllow, engine.Evaluate(src, "", dst, 443, "", ""))
}

func TestRuleEngine_EmptyProtocolsMatchAll(t *testing.T) {
	engine := NewRuleEngine(testLogger(), ActionAllow)
	engine.UpdateRules([]Rule{
		{
			ID:     "block-all-protos",
			Action: ActionBlock,
			// No Protocols field = match all protocols
			Priority: 1,
		},
	}, ActionAllow)

	src := netip.MustParseAddr("10.0.0.1")
	dst := netip.MustParseAddr("1.2.3.4")

	assert.Equal(t, ActionBlock, engine.Evaluate(src, "", dst, 443, ProtoHTTP, ""))
	assert.Equal(t, ActionBlock, engine.Evaluate(src, "", dst, 443, ProtoHTTPS, ""))
	assert.Equal(t, ActionBlock, engine.Evaluate(src, "", dst, 443, ProtoWebSocket, ""))
	assert.Equal(t, ActionBlock, engine.Evaluate(src, "", dst, 443, ProtoH2, ""))
	assert.Equal(t, ActionBlock, engine.Evaluate(src, "", dst, 443, "", ""))
}

func TestRuleEngine_UpdateRulesSortsByPriority(t *testing.T) {
	engine := NewRuleEngine(testLogger(), ActionAllow)

	engine.UpdateRules([]Rule{
		{ID: "c", Priority: 30, Action: ActionBlock},
		{ID: "a", Priority: 10, Action: ActionInspect},
		{ID: "b", Priority: 20, Action: ActionAllow},
	}, ActionAllow)

	engine.mu.RLock()
	defer engine.mu.RUnlock()

	require.Len(t, engine.rules, 3)
	assert.Equal(t, id.RuleID("a"), engine.rules[0].ID)
	assert.Equal(t, id.RuleID("b"), engine.rules[1].ID)
	assert.Equal(t, id.RuleID("c"), engine.rules[2].ID)
}
