package middleware

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFilterHeaderMutationsDoesNotTrustReservedHeaders(t *testing.T) {
	mutations := &Mutations{
		HeadersAdd: []KV{
			{Key: "x-request-label", Value: "allowed"},
			{Key: "x-netbird-user-id", Value: "spoofed-user"},
		},
		HeadersRemove: []string{"x-request-label", "x-netbird-groups"},
	}

	filteredAdd, filteredRemove, blocked := FilterHeaderMutations(mutations)

	assert.Equal(t, []KV{{Key: "x-request-label", Value: "allowed"}}, filteredAdd,
		"the public filter should retain mutable additions")
	assert.Equal(t, []string{"x-request-label"}, filteredRemove,
		"the public filter should retain mutable removals")
	assert.ElementsMatch(t, []string{"x-netbird-user-id", "x-netbird-groups"}, blocked,
		"the public filter must not grant the identity middleware exception")
}
