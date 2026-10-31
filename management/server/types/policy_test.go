package types

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/management/server/testutil"
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

func TestPolicy_EqualComparesAllFields(t *testing.T) {
	// PublicID is copied from the stored policy before comparing.
	testutil.EqualComparesAllFields(t, (*Policy).Equal, "PublicID")
}

func TestPolicyEqual_DuplicateRuleIDs(t *testing.T) {
	stored := &Policy{
		ID: "pol1",
		Rules: []*PolicyRule{
			{ID: "r1", PolicyID: "pol1", Ports: []string{"80"}},
			{ID: "r2", PolicyID: "pol1", Ports: []string{"443"}},
		},
	}
	incoming := &Policy{
		ID: "pol1",
		Rules: []*PolicyRule{
			{ID: "r1", PolicyID: "pol1", Ports: []string{"80"}},
			{ID: "r1", PolicyID: "pol1", Ports: []string{"80"}},
		},
	}
	assert.False(t, incoming.Equal(stored), "a policy repeating one rule ID must not equal one with distinct rules")
	assert.False(t, stored.Equal(incoming), "comparison with duplicate rule IDs should be symmetric")
	assert.False(t, incoming.Equal(incoming.Copy()), "a policy with duplicate rule IDs is never considered unchanged")
}

func TestPolicyEqual_NilRule(t *testing.T) {
	a := &Policy{ID: "pol1", Rules: []*PolicyRule{nil}}
	b := &Policy{ID: "pol1", Rules: []*PolicyRule{{ID: "r1"}}}
	assert.False(t, a.Equal(b), "a nil rule should not equal a real rule")
	assert.False(t, b.Equal(a), "a real rule should not equal a nil rule")
}
