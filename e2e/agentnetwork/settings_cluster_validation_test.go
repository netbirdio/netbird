//go:build e2e

package agentnetwork

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/e2e/harness"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

// TestSettingsBootstrapValidatesProxyCluster covers the bootstrap-time check
// on the picked cluster, end to end against a real proxy.
//
// The synthesised gateway service is always private: agents reach it over the
// WireGuard tunnel and are authorised by their peer identity. Only a proxy
// running embedded in a netbird client (`netbird proxy --private`) can serve
// that, and management reports it per cluster as the `private` capability —
// the same supports_private flag the dashboard reads to decide which clusters
// it may offer. The endpoint assigned at bootstrap is immutable, so pinning
// to a cluster that cannot serve it has to be refused up front rather than
// leaving the account with a dead gateway.
//
// One combined server and one cluster address, walked through three states:
// a live centralised proxy (refused), that proxy stopped so nothing in the
// cluster is live any more (still refused — the record of what the cluster is
// outlives its heartbeats), and finally an embedded proxy (accepted, the
// capability being any-true across the cluster's live proxies). Same account,
// same address, so nothing but the cluster's state accounts for the different
// answers.
func TestSettingsBootstrapValidatesProxyCluster(t *testing.T) {
	ctx := context.Background()

	fresh, err := harnessStartFresh(ctx, t)
	require.NoError(t, err, "start dedicated combined server")

	proxyToken, err := fresh.CreateProxyTokenCLI(ctx, "e2e-cluster-validation")
	require.NoError(t, err, "mint proxy token via CLI")

	const cluster = harness.AgentNetworkCluster

	// A centralised proxy: connected and serving the cluster, but not
	// embedded in a netbird client, so it cannot authenticate tunnel peers.
	central, err := harness.StartProxy(ctx, fresh, proxyToken, map[string]string{
		"NB_PROXY_PRIVATE": "false",
	})
	require.NoError(t, err, "start centralised proxy")
	// Terminated mid-test; the cleanup only covers an early failure.
	t.Cleanup(func() { _ = central.Terminate(context.Background()) })

	waitClusterPrivate(ctx, t, fresh, cluster, false)

	_, err = fresh.CreateSettings(ctx, api.AgentNetworkSettingsCreateRequest{
		ProxyAddress: ptr(cluster),
	})
	require.Error(t, err, "bootstrap onto a cluster with no embedded proxy must be refused")
	requireClientError(t, err)
	assert.Contains(t, err.Error(), "embedded proxy",
		"the refusal must name what the cluster is missing: %v", err)

	after, err := fresh.GetSettings(ctx)
	require.NoError(t, err, "settings must still read after a refused bootstrap")
	assert.Empty(t, after.Endpoint, "a refused bootstrap must not assign an endpoint")
	assert.Empty(t, after.ProxyAddress, "a refused bootstrap must not pin a cluster")

	// Stopping the centralised proxy must not turn the refusal into an
	// acceptance: the cluster's proxy rows outlive their heartbeats (only the
	// hourly stale reaper removes them), so the cluster is still on record as
	// one that cannot serve the gateway. Judging on liveness instead would
	// make "wait for the proxy to go quiet" a way to pin the account's
	// immutable endpoint to a cluster that can never serve it.
	require.NoError(t, central.Terminate(ctx), "stop the centralised proxy")
	waitClusterAbsent(ctx, t, fresh, cluster)

	_, err = fresh.CreateSettings(ctx, api.AgentNetworkSettingsCreateRequest{
		ProxyAddress: ptr(cluster),
	})
	require.Error(t, err, "an offline cluster with no embedded proxy on record must stay refused")
	requireClientError(t, err)

	// Add an embedded proxy to the same cluster: now it can serve a private
	// service, and the very same request must go through.
	embedded, err := harness.StartProxy(ctx, fresh, proxyToken)
	require.NoError(t, err, "start embedded proxy")
	t.Cleanup(func() { _ = embedded.Terminate(context.Background()) })

	waitClusterPrivate(ctx, t, fresh, cluster, true)

	bootstrapped, err := fresh.CreateSettings(ctx, api.AgentNetworkSettingsCreateRequest{
		ProxyAddress: ptr(cluster),
	})
	require.NoError(t, err, "bootstrap onto a private-capable cluster must succeed")
	assert.Equal(t, cluster, bootstrapped.ProxyAddress, "the pinned cluster is the requested one")
	assert.True(t, strings.HasSuffix(bootstrapped.Endpoint, "."+cluster),
		"the endpoint must hang one label beneath the cluster: %s", bootstrapped.Endpoint)
}

// waitClusterPrivate polls the domains endpoint — the list the dashboard picks
// its bootstrap cluster from — until the free domain for clusterAddr reports
// supports_private == want. A proxy's capabilities land when it registers, so
// this is the barrier between starting a proxy and asserting on what
// management thinks its cluster can do.
func waitClusterPrivate(ctx context.Context, t *testing.T, c *harness.Combined, clusterAddr string, want bool) {
	t.Helper()

	deadline := time.Now().Add(90 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		domains, err := c.API().ReverseProxyDomains.List(ctx)
		if err != nil {
			last = "list domains: " + err.Error()
		} else {
			last = "cluster not listed"
			for _, d := range domains {
				if d.Domain != clusterAddr {
					continue
				}
				if d.SupportsPrivate == nil {
					last = "supports_private not reported yet"
					break
				}
				if *d.SupportsPrivate == want {
					return
				}
				last = "supports_private is not the expected value"
				break
			}
		}
		if !waitBeforeRetry(ctx, 2*time.Second) {
			break
		}
	}
	t.Fatalf("cluster %s never reported supports_private=%v: %s", clusterAddr, want, last)
}

// waitClusterAbsent polls the domains endpoint until clusterAddr is no longer
// offered, i.e. management sees no live proxy in it. The free-domain list is
// built from the active clusters, so this is how a proxy going away becomes
// observable — while the cluster's rows, and so its capability record, remain.
func waitClusterAbsent(ctx context.Context, t *testing.T, c *harness.Combined, clusterAddr string) {
	t.Helper()

	deadline := time.Now().Add(90 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		domains, err := c.API().ReverseProxyDomains.List(ctx)
		if err != nil {
			last = "list domains: " + err.Error()
		} else {
			listed := false
			for _, d := range domains {
				if d.Domain == clusterAddr {
					listed = true
					break
				}
			}
			if !listed {
				return
			}
			last = "cluster still listed as active"
		}
		if !waitBeforeRetry(ctx, 2*time.Second) {
			break
		}
	}
	t.Fatalf("cluster %s never dropped out of the active list: %s", clusterAddr, last)
}
