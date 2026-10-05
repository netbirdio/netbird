//go:build e2e

package agentnetwork

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCombinedBootstrap proves Pillar 1: the shared combined server came up and
// the /api/setup-minted PAT authenticates a real management API call through
// the typed REST client (the bootstrap itself ran in TestMain).
func TestCombinedBootstrap(t *testing.T) {
	ctx := context.Background()

	require.NotEmpty(t, srv.PAT, "TestMain must have minted an admin PAT")

	users, err := srv.API().Users.List(ctx)
	require.NoError(t, err, "authenticated Users.List must round-trip")
	require.NotEmpty(t, users, "the bootstrapped account must have at least one user")

	var emails []string
	for _, u := range users {
		emails = append(emails, u.Email)
	}
	assert.Contains(t, emails, "admin@netbird.test", "the bootstrapped owner should appear in the users list")
}
