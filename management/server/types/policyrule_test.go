package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPolicyRuleEqual_SamePortsDifferentOrder(t *testing.T) {
	a := &PolicyRule{
		ID:       "rule1",
		PolicyID: "pol1",
		Ports:    []string{"443", "80", "22"},
	}
	b := &PolicyRule{
		ID:       "rule1",
		PolicyID: "pol1",
		Ports:    []string{"22", "443", "80"},
	}
	assert.True(t, a.Equal(b))
}

func TestPolicyRuleEqual_DifferentPorts(t *testing.T) {
	a := &PolicyRule{
		ID:       "rule1",
		PolicyID: "pol1",
		Ports:    []string{"443", "80"},
	}
	b := &PolicyRule{
		ID:       "rule1",
		PolicyID: "pol1",
		Ports:    []string{"443", "22"},
	}
	assert.False(t, a.Equal(b))
}

func TestPolicyRuleEqual_SourcesDestinationsDifferentOrder(t *testing.T) {
	a := &PolicyRule{
		ID:           "rule1",
		PolicyID:     "pol1",
		Sources:      []string{"g1", "g2", "g3"},
		Destinations: []string{"g4", "g5"},
	}
	b := &PolicyRule{
		ID:           "rule1",
		PolicyID:     "pol1",
		Sources:      []string{"g3", "g1", "g2"},
		Destinations: []string{"g5", "g4"},
	}
	assert.True(t, a.Equal(b))
}

func TestPolicyRuleEqual_DifferentSources(t *testing.T) {
	a := &PolicyRule{
		ID:       "rule1",
		PolicyID: "pol1",
		Sources:  []string{"g1", "g2"},
	}
	b := &PolicyRule{
		ID:       "rule1",
		PolicyID: "pol1",
		Sources:  []string{"g1", "g3"},
	}
	assert.False(t, a.Equal(b))
}

func TestPolicyRuleEqual_PortRangesDifferentOrder(t *testing.T) {
	a := &PolicyRule{
		ID:       "rule1",
		PolicyID: "pol1",
		PortRanges: []RulePortRange{
			{Start: 8000, End: 9000},
			{Start: 80, End: 80},
		},
	}
	b := &PolicyRule{
		ID:       "rule1",
		PolicyID: "pol1",
		PortRanges: []RulePortRange{
			{Start: 80, End: 80},
			{Start: 8000, End: 9000},
		},
	}
	assert.True(t, a.Equal(b))
}

func TestPolicyRuleEqual_DifferentPortRanges(t *testing.T) {
	a := &PolicyRule{
		ID:       "rule1",
		PolicyID: "pol1",
		PortRanges: []RulePortRange{
			{Start: 80, End: 80},
		},
	}
	b := &PolicyRule{
		ID:       "rule1",
		PolicyID: "pol1",
		PortRanges: []RulePortRange{
			{Start: 80, End: 443},
		},
	}
	assert.False(t, a.Equal(b))
}

func TestPolicyRuleEqual_AuthorizedGroupsDifferentValueOrder(t *testing.T) {
	a := &PolicyRule{
		ID:       "rule1",
		PolicyID: "pol1",
		AuthorizedGroups: map[string][]string{
			"g1": {"u1", "u2", "u3"},
		},
	}
	b := &PolicyRule{
		ID:       "rule1",
		PolicyID: "pol1",
		AuthorizedGroups: map[string][]string{
			"g1": {"u3", "u1", "u2"},
		},
	}
	assert.True(t, a.Equal(b))
}

func TestPolicyRuleEqual_DifferentAuthorizedGroups(t *testing.T) {
	a := &PolicyRule{
		ID:       "rule1",
		PolicyID: "pol1",
		AuthorizedGroups: map[string][]string{
			"g1": {"u1"},
		},
	}
	b := &PolicyRule{
		ID:       "rule1",
		PolicyID: "pol1",
		AuthorizedGroups: map[string][]string{
			"g2": {"u1"},
		},
	}
	assert.False(t, a.Equal(b))
}

func TestPolicyRuleEqual_DifferentScalarFields(t *testing.T) {
	base := PolicyRule{
		ID:            "rule1",
		PolicyID:      "pol1",
		Name:          "test",
		Description:   "desc",
		Enabled:       true,
		Action:        PolicyTrafficActionAccept,
		Bidirectional: true,
		Protocol:      PolicyRuleProtocolTCP,
	}

	other := base
	other.Name = "changed"
	assert.False(t, base.Equal(&other))

	other = base
	other.Enabled = false
	assert.False(t, base.Equal(&other))

	other = base
	other.Action = PolicyTrafficActionDrop
	assert.False(t, base.Equal(&other))

	other = base
	other.Protocol = PolicyRuleProtocolUDP
	assert.False(t, base.Equal(&other))
}

func TestPolicyRuleEqual_NilCases(t *testing.T) {
	var a *PolicyRule
	var b *PolicyRule
	assert.True(t, a.Equal(b))

	a = &PolicyRule{ID: "rule1"}
	assert.False(t, a.Equal(nil))
}

func TestPolicyRuleEqual_EmptySlices(t *testing.T) {
	a := &PolicyRule{
		ID:       "rule1",
		PolicyID: "pol1",
		Ports:    []string{},
		Sources:  nil,
	}
	b := &PolicyRule{
		ID:       "rule1",
		PolicyID: "pol1",
		Ports:    nil,
		Sources:  []string{},
	}
	assert.True(t, a.Equal(b))
}

func TestPolicyRuleNormalize(t *testing.T) {
	rule := &PolicyRule{
		Sources:      []string{"g3", "g1", "g2"},
		Destinations: []string{"g6", "g4", "g5"},
		Ports:        []string{"443", "80", "22"},
		PortRanges: []RulePortRange{
			{Start: 8000, End: 9000},
			{Start: 80, End: 80},
			{Start: 80, End: 443},
		},
		AuthorizedGroups: map[string][]string{
			"g1": {"u3", "u1", "u2"},
		},
	}
	rule.Normalize()

	assert.Equal(t, []string{"g1", "g2", "g3"}, rule.Sources)
	assert.Equal(t, []string{"g4", "g5", "g6"}, rule.Destinations)
	assert.Equal(t, []string{"22", "443", "80"}, rule.Ports)
	assert.Equal(t, []RulePortRange{
		{Start: 80, End: 80},
		{Start: 80, End: 443},
		{Start: 8000, End: 9000},
	}, rule.PortRanges)
	assert.Equal(t, []string{"u1", "u2", "u3"}, rule.AuthorizedGroups["g1"])
}

func TestPolicyRuleNormalize_Nil(t *testing.T) {
	var rule *PolicyRule
	rule.Normalize()
}
