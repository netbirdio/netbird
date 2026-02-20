package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPolicyEqual_SameRulesDifferentOrder(t *testing.T) {
	a := &Policy{
		ID:        "pol1",
		AccountID: "acc1",
		Name:      "test",
		Enabled:   true,
		Rules: []*PolicyRule{
			{ID: "r1", PolicyID: "pol1", Ports: []string{"80"}},
			{ID: "r2", PolicyID: "pol1", Ports: []string{"443"}},
		},
	}
	b := &Policy{
		ID:        "pol1",
		AccountID: "acc1",
		Name:      "test",
		Enabled:   true,
		Rules: []*PolicyRule{
			{ID: "r2", PolicyID: "pol1", Ports: []string{"443"}},
			{ID: "r1", PolicyID: "pol1", Ports: []string{"80"}},
		},
	}
	assert.True(t, a.Equal(b))
}

func TestPolicyEqual_DifferentRules(t *testing.T) {
	a := &Policy{
		ID:      "pol1",
		Enabled: true,
		Rules: []*PolicyRule{
			{ID: "r1", PolicyID: "pol1", Ports: []string{"80"}},
		},
	}
	b := &Policy{
		ID:      "pol1",
		Enabled: true,
		Rules: []*PolicyRule{
			{ID: "r1", PolicyID: "pol1", Ports: []string{"443"}},
		},
	}
	assert.False(t, a.Equal(b))
}

func TestPolicyEqual_DifferentRuleCount(t *testing.T) {
	a := &Policy{
		ID: "pol1",
		Rules: []*PolicyRule{
			{ID: "r1", PolicyID: "pol1"},
		},
	}
	b := &Policy{
		ID: "pol1",
		Rules: []*PolicyRule{
			{ID: "r1", PolicyID: "pol1"},
			{ID: "r2", PolicyID: "pol1"},
		},
	}
	assert.False(t, a.Equal(b))
}

func TestPolicyEqual_PostureChecksDifferentOrder(t *testing.T) {
	a := &Policy{
		ID:                  "pol1",
		SourcePostureChecks: []string{"pc3", "pc1", "pc2"},
	}
	b := &Policy{
		ID:                  "pol1",
		SourcePostureChecks: []string{"pc1", "pc2", "pc3"},
	}
	assert.True(t, a.Equal(b))
}

func TestPolicyEqual_DifferentPostureChecks(t *testing.T) {
	a := &Policy{
		ID:                  "pol1",
		SourcePostureChecks: []string{"pc1", "pc2"},
	}
	b := &Policy{
		ID:                  "pol1",
		SourcePostureChecks: []string{"pc1", "pc3"},
	}
	assert.False(t, a.Equal(b))
}

func TestPolicyEqual_DifferentScalarFields(t *testing.T) {
	base := Policy{
		ID:          "pol1",
		AccountID:   "acc1",
		Name:        "test",
		Description: "desc",
		Enabled:     true,
	}

	other := base
	other.Name = "changed"
	assert.False(t, base.Equal(&other))

	other = base
	other.Enabled = false
	assert.False(t, base.Equal(&other))

	other = base
	other.Description = "changed"
	assert.False(t, base.Equal(&other))
}

func TestPolicyEqual_NilCases(t *testing.T) {
	var a *Policy
	var b *Policy
	assert.True(t, a.Equal(b))

	a = &Policy{ID: "pol1"}
	assert.False(t, a.Equal(nil))
}

func TestPolicyEqual_RulesMismatchByID(t *testing.T) {
	a := &Policy{
		ID: "pol1",
		Rules: []*PolicyRule{
			{ID: "r1", PolicyID: "pol1"},
		},
	}
	b := &Policy{
		ID: "pol1",
		Rules: []*PolicyRule{
			{ID: "r2", PolicyID: "pol1"},
		},
	}
	assert.False(t, a.Equal(b))
}

func TestPolicyNormalize(t *testing.T) {
	p := &Policy{
		SourcePostureChecks: []string{"pc3", "pc1", "pc2"},
		Rules: []*PolicyRule{
			{
				ID:           "r1",
				Sources:      []string{"g2", "g1"},
				Destinations: []string{"g4", "g3"},
				Ports:        []string{"443", "80"},
			},
		},
	}
	p.Normalize()

	assert.Equal(t, []string{"pc1", "pc2", "pc3"}, p.SourcePostureChecks)
	assert.Equal(t, []string{"g1", "g2"}, p.Rules[0].Sources)
	assert.Equal(t, []string{"g3", "g4"}, p.Rules[0].Destinations)
	assert.Equal(t, []string{"443", "80"}, p.Rules[0].Ports)
}

func TestPolicyNormalize_Nil(t *testing.T) {
	var p *Policy
	p.Normalize()
}

func TestPolicyEqual_FullScenario(t *testing.T) {
	a := &Policy{
		ID:                  "pol1",
		AccountID:           "acc1",
		Name:                "Web Access",
		Description:         "Allow web access",
		Enabled:             true,
		SourcePostureChecks: []string{"pc2", "pc1"},
		Rules: []*PolicyRule{
			{
				ID:            "r1",
				PolicyID:      "pol1",
				Name:          "HTTP",
				Enabled:       true,
				Action:        PolicyTrafficActionAccept,
				Protocol:      PolicyRuleProtocolTCP,
				Bidirectional: true,
				Sources:       []string{"g2", "g1"},
				Destinations:  []string{"g4", "g3"},
				Ports:         []string{"443", "80", "8080"},
				PortRanges: []RulePortRange{
					{Start: 8000, End: 9000},
					{Start: 80, End: 80},
				},
			},
		},
	}
	b := &Policy{
		ID:                  "pol1",
		AccountID:           "acc1",
		Name:                "Web Access",
		Description:         "Allow web access",
		Enabled:             true,
		SourcePostureChecks: []string{"pc1", "pc2"},
		Rules: []*PolicyRule{
			{
				ID:            "r1",
				PolicyID:      "pol1",
				Name:          "HTTP",
				Enabled:       true,
				Action:        PolicyTrafficActionAccept,
				Protocol:      PolicyRuleProtocolTCP,
				Bidirectional: true,
				Sources:       []string{"g1", "g2"},
				Destinations:  []string{"g3", "g4"},
				Ports:         []string{"80", "8080", "443"},
				PortRanges: []RulePortRange{
					{Start: 80, End: 80},
					{Start: 8000, End: 9000},
				},
			},
		},
	}
	assert.True(t, a.Equal(b))
}
