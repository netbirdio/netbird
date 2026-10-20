//go:build e2e

package agentnetwork

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/e2e/harness"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

// harnessStartFresh boots a dedicated combined server with its own fresh
// account and registers its teardown on t. Unlike the shared srv, the fresh
// account has NOT had its agent-network endpoint bootstrapped.
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

// TestSettingsBootstrapViaPost covers the explicit bootstrap contract on an
// account that has never been bootstrapped: the GET reads as the defaults
// with an empty endpoint/proxy_address, a PUT has no row to update and fails,
// and a POST creates the row and assigns the immutable endpoint — labeled
// beneath a proxy address here, with the toggle overrides from the same
// request applied. The shared srv cannot provide that starting state
// (TestMain bootstraps it), so this boots a dedicated combined server — the
// image is already built and cached by TestMain's StartCombined, so the extra
// cost is one container start.
func TestSettingsBootstrapViaPost(t *testing.T) {
	ctx := context.Background()

	fresh, err := harnessStartFresh(ctx, t)
	require.NoError(t, err, "start dedicated combined server")

	// Before agent-network bootstrap the settings read as the defaults, not
	// as an error and not as a null body.
	before, err := fresh.GetSettings(ctx)
	require.NoError(t, err, "get settings on a fresh account must succeed")
	assert.Empty(t, before.Endpoint, "endpoint must be empty before bootstrap")
	assert.Empty(t, before.ProxyAddress, "proxy address must be empty before bootstrap")
	assert.False(t, before.Dedicated, "an unbootstrapped account has no serving shape")
	assert.True(t, before.EnableLogCollection, "defaults must show log collection on, matching bootstrap")
	assert.False(t, before.EnablePromptCollection, "defaults must show prompt collection off")

	// A PUT has no row to update yet — bootstrap is the explicit POST.
	_, err = fresh.UpdateSettings(ctx, api.AgentNetworkSettingsRequest{
		EnableLogCollection:    true,
		AccessLogRetentionDays: 30,
	})
	requireClientError(t, err)

	// A POST with a proxy address bootstraps a labeled endpoint and applies
	// the toggles from the same request. Every toggle is set away from its
	// bootstrap default so each assertion can actually fail.
	const cluster = "e2e.bootstrap.netbird.selfhosted"
	bootstrapped, err := fresh.CreateSettings(ctx, api.AgentNetworkSettingsCreateRequest{
		ProxyAddress:           ptr(cluster),
		EnableLogCollection:    ptr(false),
		EnablePromptCollection: ptr(true),
		RedactPii:              ptr(true),
	})
	require.NoError(t, err, "bootstrap settings via POST must succeed")
	assert.Equal(t, cluster, bootstrapped.ProxyAddress, "proxy address must be pinned from the request")
	require.NotEmpty(t, bootstrapped.Endpoint, "endpoint must be assigned at bootstrap")
	assert.True(t, strings.HasSuffix(bootstrapped.Endpoint, "."+cluster),
		"labeled endpoint must hang one label beneath the proxy address: %s", bootstrapped.Endpoint)
	assert.False(t, bootstrapped.Dedicated, "a labeled pin is not dedicated")
	assert.False(t, bootstrapped.EnableLogCollection, "log collection from the bootstrap request must override the default")
	assert.True(t, bootstrapped.EnablePromptCollection, "prompt collection from the bootstrap request must apply")
	assert.True(t, bootstrapped.RedactPii, "redact toggle from the bootstrap request must apply")

	// The row is persisted: an independent read agrees on every field.
	after, err := fresh.GetSettings(ctx)
	require.NoError(t, err, "get settings after bootstrap must succeed")
	assert.Equal(t, bootstrapped.Endpoint, after.Endpoint, "bootstrap must persist across reads")
	assert.Equal(t, bootstrapped.EnableLogCollection, after.EnableLogCollection, "log collection must persist")
	assert.Equal(t, bootstrapped.EnablePromptCollection, after.EnablePromptCollection, "prompt collection must persist")
	assert.Equal(t, bootstrapped.RedactPii, after.RedactPii, "redact toggle must persist")

	// Once bootstrapped, PUT updates the toggles. The identity fields ride
	// along as a required echo of the assigned values; a matching echo is
	// accepted and never written.
	persisted, err := fresh.UpdateSettings(ctx, api.AgentNetworkSettingsRequest{
		Endpoint:               bootstrapped.Endpoint,
		ProxyAddress:           bootstrapped.ProxyAddress,
		EnableLogCollection:    true,
		EnablePromptCollection: false,
		RedactPii:              true,
		AccessLogRetentionDays: 21,
	})
	require.NoError(t, err, "post-bootstrap update must succeed")
	require.NotNil(t, persisted.AccessLogRetentionDays)
	assert.Equal(t, 21, *persisted.AccessLogRetentionDays, "retention from the update must apply")
	assert.Equal(t, bootstrapped.Endpoint, persisted.Endpoint, "endpoint must survive updates untouched")
	assert.Equal(t, cluster, persisted.ProxyAddress, "proxy address must survive updates untouched")
	assert.True(t, persisted.EnableLogCollection, "post-bootstrap toggle must apply")
	assert.False(t, persisted.EnablePromptCollection, "post-bootstrap toggle must apply")

	// The endpoint is immutable: a PUT carrying a different endpoint is
	// rejected, and a second bootstrap is rejected as a conflict. Neither
	// rejected write may disturb anything.
	_, err = fresh.UpdateSettings(ctx, api.AgentNetworkSettingsRequest{
		Endpoint:               "other.cluster.invalid",
		ProxyAddress:           persisted.ProxyAddress,
		EnableLogCollection:    persisted.EnableLogCollection,
		EnablePromptCollection: persisted.EnablePromptCollection,
		RedactPii:              persisted.RedactPii,
		AccessLogRetentionDays: 21,
	})
	requireClientError(t, err)

	_, err = fresh.CreateSettings(ctx, api.AgentNetworkSettingsCreateRequest{
		Endpoint: ptr("other.cluster.invalid"),
	})
	requireClientError(t, err)

	final, err := fresh.GetSettings(ctx)
	require.NoError(t, err, "get settings after the rejected bootstrap must succeed")
	assert.Equal(t, persisted.Endpoint, final.Endpoint, "rejected bootstrap must not change the endpoint")
	assert.Equal(t, persisted.ProxyAddress, final.ProxyAddress, "rejected bootstrap must not change the proxy address")
	assert.Equal(t, persisted.EnableLogCollection, final.EnableLogCollection, "rejected bootstrap must not apply its toggles")
	assert.Equal(t, persisted.EnablePromptCollection, final.EnablePromptCollection, "rejected bootstrap must not apply its toggles")
	assert.Equal(t, persisted.RedactPii, final.RedactPii, "rejected bootstrap must not apply its toggles")
}

// TestSettingsBootstrapSelfAddressed covers the dedicated shape end to end:
// a POST carrying an endpoint claims the hostname verbatim, the proxy address
// equals it, and the pin reads as dedicated — the address-first flow a
// self-hosted operator uses before deploying the proxy that will declare it.
// The tail covers the recovery path the guarded DELETE exists for: with no
// providers and no proxy at the address, the claim can be released and a
// fresh bootstrap succeeds — the fix for a typo'd immutable endpoint.
func TestSettingsBootstrapSelfAddressed(t *testing.T) {
	ctx := context.Background()

	fresh, err := harnessStartFresh(ctx, t)
	require.NoError(t, err, "start dedicated combined server")

	created, err := fresh.CreateSettings(ctx, api.AgentNetworkSettingsCreateRequest{
		Endpoint: ptr("gw.e2e.netbird.selfhosted"),
	})
	require.NoError(t, err, "self-addressed bootstrap must succeed")
	assert.Equal(t, "gw.e2e.netbird.selfhosted", created.Endpoint, "endpoint must be claimed verbatim")
	assert.Equal(t, created.Endpoint, created.ProxyAddress, "self-addressed: proxy address is the endpoint")
	assert.True(t, created.Dedicated, "a self-addressed pin is dedicated")

	// No providers exist and no proxy declares the address, so both delete
	// guards are clear: the delete releases the claim and the account reads
	// as unbootstrapped defaults again.
	require.NoError(t, fresh.DeleteSettings(ctx), "guarded delete with both guards clear must succeed")

	after, err := fresh.GetSettings(ctx)
	require.NoError(t, err, "get settings after delete must succeed")
	assert.Empty(t, after.Endpoint, "a deleted account must read as unbootstrapped")

	// A second delete has nothing to remove.
	requireClientError(t, fresh.DeleteSettings(ctx))

	// Re-creating is a fresh bootstrap — the released hostname is free to be
	// claimed again, or a different one chosen.
	recreated, err := fresh.CreateSettings(ctx, api.AgentNetworkSettingsCreateRequest{
		Endpoint: ptr("gw2.e2e.netbird.selfhosted"),
	})
	require.NoError(t, err, "bootstrap after delete must succeed")
	assert.Equal(t, "gw2.e2e.netbird.selfhosted", recreated.Endpoint, "the fresh bootstrap claims the new hostname")
}
