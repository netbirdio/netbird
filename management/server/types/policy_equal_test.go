package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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
