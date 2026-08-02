//go:build e2e

package agentnetwork

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/e2e/harness"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

// harnessStartFresh boots a dedicated combined server with its own fresh
// account and registers its teardown on t.
func harnessStartFresh(ctx context.Context, t *testing.T) (*harness.Combined, error) {
	t.Helper()
	fresh, err := harness.StartCombined(ctx)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = fresh.Terminate(context.Background()) })
	if _, err := fresh.Bootstrap(ctx); err != nil {
		return nil, err
	}
	return fresh, nil
}

// TestSettingsBootstrapViaPut covers the settings-first bootstrap path on an
// account that has never been bootstrapped: the GET reads as the defaults
// with an empty cluster/subdomain/endpoint, a PUT without a cluster has
// nothing to pin and fails, and a PUT carrying a cluster creates the row and
// pins it immutably. The shared srv cannot provide that starting state (any
// provider-creating test bootstraps it, and test order is deliberately not
// relied on), so this boots a dedicated combined server — the image is
// already built and cached by TestMain's StartCombined, so the extra cost is
// one container start.
func TestSettingsBootstrapViaPut(t *testing.T) {
	ctx := context.Background()

	fresh, err := harnessStartFresh(ctx, t)
	require.NoError(t, err, "start dedicated combined server")

	// Before agent-network bootstrap the settings read as the defaults, not
	// as an error and not as a null body.
	before, err := fresh.GetSettings(ctx)
	require.NoError(t, err, "get settings on a fresh account must succeed")
	assert.Empty(t, before.Cluster, "cluster must be empty before bootstrap")
	assert.Empty(t, before.Subdomain, "subdomain must be empty before bootstrap")
	assert.Empty(t, before.Endpoint, "endpoint must be empty before bootstrap, not a bare dot")
	assert.True(t, before.EnableLogCollection, "defaults must show log collection on, matching bootstrap")
	assert.False(t, before.EnablePromptCollection, "defaults must show prompt collection off")

	// A PUT without a cluster has nothing to pin the account to.
	_, err = fresh.UpdateSettings(ctx, api.AgentNetworkSettingsRequest{
		EnableLogCollection: true,
	})
	requireClientError(t, err)

	// A PUT carrying a cluster bootstraps the account and applies the
	// mutable fields from the same request.
	const cluster = "e2e.bootstrap.netbird.selfhosted"
	bootstrapped, err := fresh.UpdateSettings(ctx, api.AgentNetworkSettingsRequest{
		Cluster:                ptr(cluster),
		EnableLogCollection:    true,
		EnablePromptCollection: true,
		RedactPii:              false,
	})
	require.NoError(t, err, "bootstrap settings via PUT must succeed")
	assert.Equal(t, cluster, bootstrapped.Cluster, "cluster must be pinned from the request")
	require.NotEmpty(t, bootstrapped.Subdomain, "subdomain must be assigned at bootstrap")
	assert.Equal(t, bootstrapped.Subdomain+"."+cluster, bootstrapped.Endpoint, "endpoint must combine subdomain and cluster")
	assert.True(t, bootstrapped.EnablePromptCollection, "toggle from the bootstrap request must apply")

	// The row is persisted and the cluster immutable: reads agree, and a
	// different cluster is rejected rather than silently ignored.
	after, err := fresh.GetSettings(ctx)
	require.NoError(t, err, "get settings after bootstrap must succeed")
	assert.Equal(t, bootstrapped.Endpoint, after.Endpoint, "bootstrap must persist across reads")

	_, err = fresh.UpdateSettings(ctx, api.AgentNetworkSettingsRequest{
		Cluster:             ptr("other.cluster.invalid"),
		EnableLogCollection: true,
	})
	requireClientError(t, err)
}
