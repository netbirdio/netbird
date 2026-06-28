//go:build e2e

package agentnetwork

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/e2e/harness"
)

// TestCombinedBootstrap proves Pillar 1: a combined NetBird server comes up in a
// container, the /api/setup bootstrap mints an admin PAT with no OIDC, and that
// PAT authenticates real management API calls through the typed REST client.
func TestCombinedBootstrap(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	srv, err := harness.StartCombined(ctx)
	require.NoError(t, err, "combined server must build and start")
	t.Cleanup(func() {
		_ = srv.Terminate(context.Background())
	})

	pat, err := srv.Bootstrap(ctx)
	require.NoError(t, err, "/api/setup must mint an admin PAT")
	require.NotEmpty(t, pat, "PAT must be non-empty")

	// The PAT must authenticate a real management API call through the client.
	users, err := srv.API().Users.List(ctx)
	require.NoError(t, err, "authenticated Users.List must round-trip")
	require.NotEmpty(t, users, "the bootstrapped account must have at least one user")

	var emails []string
	for _, u := range users {
		emails = append(emails, u.Email)
	}
	assert.Contains(t, emails, "admin@netbird.test", "the bootstrapped owner should appear in the users list")
}
