package mdm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The same spellings, through the conflict check that decides whether a request
// is refused. An enforced URL restated in another spelling addresses the very
// server the policy names, so it must not be reported as a conflict.
func TestConflictURLComparesEndpoints(t *testing.T) {
	policy := NewPolicy(map[string]any{KeyManagementURL: "https://mgmt.example.com"})
	require.True(t, policy.HasKey(KeyManagementURL))

	for _, restated := range []string{
		"https://mgmt.example.com",
		"https://mgmt.example.com:443",
		"https://mgmt.example.com/",
		"https://MGMT.example.com",
		"https://mgmt.example.com:0443",
	} {
		conflicts := ResolveConflicts(policy, []ConflictCheck{ConflictURL(KeyManagementURL, restated)})
		assert.Empty(t, conflicts, "%q is the enforced endpoint written differently", restated)
	}

	for _, diverging := range []string{
		"https://other.example.com",
		"http://mgmt.example.com",
		"https://mgmt.example.com:8443",
		"https://mgmt.example.com/other",
	} {
		conflicts := ResolveConflicts(policy, []ConflictCheck{ConflictURL(KeyManagementURL, diverging)})
		assert.Equal(t, []string{KeyManagementURL}, conflicts, "%q addresses another endpoint", diverging)
	}

	// An unset field is not a request to change anything.
	assert.Empty(t, ResolveConflicts(policy, []ConflictCheck{ConflictURL(KeyManagementURL, "")}))
}
