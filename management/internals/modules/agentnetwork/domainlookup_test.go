package agentnetwork

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/store"
)

// TestSynthesizeServiceForDomain_ResolvesZoneBasedEndpoint — with a Zone the
// hostname's parent is the zone, not the cluster, so the old "strip the first
// label and match a cluster" prefilter found nothing and every zone-based
// tenant failed to resolve on the auth path.
func TestSynthesizeServiceForDomain_ResolvesZoneBasedEndpoint(t *testing.T) {
	ctx := context.Background()
	s, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err, "real sqlite test store must come up")
	defer cleanup()

	settings := newSynthTestSettings()
	settings.Cluster = "eu.proxy.netbird.io"
	settings.Zone = "gateway.netbird.ai"
	settings.Subdomain = "brave-otter"
	require.NoError(t, s.SaveAgentNetworkSettings(ctx, settings))
	provider := newSynthTestProvider()
	require.NoError(t, s.SaveAgentNetworkProvider(ctx, provider))
	require.NoError(t, s.SaveAgentNetworkPolicy(ctx, newSynthTestPolicy(provider.ID, "grp-eng", "")))

	domain := "brave-otter.gateway.netbird.ai"
	svc, err := SynthesizeServiceForDomain(ctx, s, domain)
	require.NoError(t, err)
	require.NotNil(t, svc, "zone-based endpoint must resolve to the owning account's service")
	assert.Equal(t, domain, svc.Domain)
}

// TestSynthesizeServiceForDomain_ResolvesLegacyClusterEndpoint — the
// non-breaking guarantee. A row with no Zone still resolves at
// <subdomain>.<cluster>, because the subdomain is the first label either way.
func TestSynthesizeServiceForDomain_ResolvesLegacyClusterEndpoint(t *testing.T) {
	ctx := context.Background()
	s, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err, "real sqlite test store must come up")
	defer cleanup()

	settings := newSynthTestSettings()
	settings.Cluster = "eu.proxy.netbird.io"
	settings.Zone = ""
	settings.Subdomain = "swift-heron"
	require.NoError(t, s.SaveAgentNetworkSettings(ctx, settings))
	provider := newSynthTestProvider()
	require.NoError(t, s.SaveAgentNetworkProvider(ctx, provider))
	require.NoError(t, s.SaveAgentNetworkPolicy(ctx, newSynthTestPolicy(provider.ID, "grp-eng", "")))

	domain := "swift-heron.eu.proxy.netbird.io"
	svc, err := SynthesizeServiceForDomain(ctx, s, domain)
	require.NoError(t, err)
	require.NotNil(t, svc, "legacy cluster-based endpoint must still resolve")
	assert.Equal(t, domain, svc.Domain)
}

// TestSynthesizeServiceForDomain_LabelMatchesButParentDoesNot — the label is
// globally unique, so a lookup by first label can hit a row that does NOT own
// the queried hostname. That must resolve to nothing rather than to the wrong
// account's service.
func TestSynthesizeServiceForDomain_LabelMatchesButParentDoesNot(t *testing.T) {
	ctx := context.Background()
	s, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err, "real sqlite test store must come up")
	defer cleanup()

	settings := newSynthTestSettings()
	settings.Cluster = "eu.proxy.netbird.io"
	settings.Zone = "gateway.netbird.ai"
	settings.Subdomain = "brave-otter"
	require.NoError(t, s.SaveAgentNetworkSettings(ctx, settings))
	provider := newSynthTestProvider()
	require.NoError(t, s.SaveAgentNetworkProvider(ctx, provider))
	require.NoError(t, s.SaveAgentNetworkPolicy(ctx, newSynthTestPolicy(provider.ID, "grp-eng", "")))

	svc, err := SynthesizeServiceForDomain(ctx, s, "brave-otter.someone-elses.zone")
	require.NoError(t, err)
	assert.Nil(t, svc, "label matched a different endpoint's parent; must not resolve to the wrong account")
}

// TestSynthesizeServiceForDomain_UnknownLabel — a hostname whose first label
// belongs to no account is a miss, not an error: the caller falls back to the
// persisted-service lookup and a returned error would mask that.
func TestSynthesizeServiceForDomain_UnknownLabel(t *testing.T) {
	ctx := context.Background()
	s, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err, "real sqlite test store must come up")
	defer cleanup()

	svc, err := SynthesizeServiceForDomain(ctx, s, "nobody-home.gateway.netbird.ai")
	require.NoError(t, err)
	assert.Nil(t, svc, "unknown label must be a miss, not an error")
}

// TestSynthesizeServiceForDomain_DegenerateInput — empty and single-label
// hostnames have no dot to cut a subdomain label from, so they resolve to no
// service, same as any other unowned hostname. The early-return guard that
// catches them is an optimisation (it skips a store round trip that would
// only miss anyway), not what makes this case correct — "" and "localhost"
// would still come back nil, nil even without it, via the same not-found
// fallthrough TestSynthesizeServiceForDomain_UnknownLabel exercises.
func TestSynthesizeServiceForDomain_DegenerateInput(t *testing.T) {
	ctx := context.Background()
	s, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err, "real sqlite test store must come up")
	defer cleanup()

	for _, domain := range []string{"", "localhost"} {
		svc, err := SynthesizeServiceForDomain(ctx, s, domain)
		require.NoError(t, err, "domain %q", domain)
		assert.Nil(t, svc, "domain %q has no subdomain label to look up", domain)
	}
}
