package store

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
)

// Capabilities travel proxy → gRPC → embedded gorm columns → aggregation → API.
// A field dropped at any of those hops reads as "capability absent", which is
// indistinguishable from a proxy that never reported it: the dashboard simply
// hides the feature and nothing fails. These assertions cover the persistence
// and aggregation hops.
func TestSqlStore_ClusterCapabilityAggregation(t *testing.T) {
	if os.Getenv("CI") == "true" && (runtime.GOOS == "darwin" || runtime.GOOS == "windows") {
		t.Skip("skip CI tests on darwin and windows")
	}

	yes, no := true, false

	tests := []struct {
		name          string
		reported      []*bool // one entry per connected proxy in the cluster
		wantAppSec    *bool
		wantAssertion string
	}{
		{
			name:          "unreported stays unknown",
			reported:      []*bool{nil},
			wantAppSec:    nil,
			wantAssertion: "an unreported capability must not read as false",
		},
		{
			name:          "single proxy reporting true",
			reported:      []*bool{&yes},
			wantAppSec:    &yes,
			wantAssertion: "a reported capability must survive persistence",
		},
		{
			name:          "one proxy without it disables the cluster",
			reported:      []*bool{&yes, &no},
			wantAppSec:    &no,
			wantAssertion: "capability must be unanimous, so a rolling upgrade cannot leave traffic uninspected",
		},
		{
			name:          "one proxy yet to report disables the cluster",
			reported:      []*bool{&yes, nil},
			wantAppSec:    &no,
			wantAssertion: "a proxy that has not reported must not count as capable",
		},
	}

	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		ctx := context.Background()
		for i, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				cluster := fmt.Sprintf("cluster-%d.proxy.example", i)
				for j, reported := range tt.reported {
					require.NoError(t, store.SaveProxy(ctx, &proxy.Proxy{
						ID:             fmt.Sprintf("proxy-%d-%d", i, j),
						ClusterAddress: cluster,
						Status:         proxy.StatusConnected,
						LastSeen:       time.Now(),
						Capabilities:   proxy.Capabilities{SupportsAppsec: reported},
					}))
				}

				got := store.GetClusterSupportsAppSec(ctx, cluster)
				if tt.wantAppSec == nil {
					assert.Nil(t, got, tt.wantAssertion)
					return
				}
				require.NotNil(t, got, tt.wantAssertion)
				assert.Equal(t, *tt.wantAppSec, *got, tt.wantAssertion)
			})
		}
	})
}

// AppSec and IP reputation are separate endpoints, so a cluster can have either
// without the other. Gating one on the other would silently disable a feature
// the operator configured.
func TestSqlStore_ClusterCapabilitiesAreIndependent(t *testing.T) {
	if os.Getenv("CI") == "true" && (runtime.GOOS == "darwin" || runtime.GOOS == "windows") {
		t.Skip("skip CI tests on darwin and windows")
	}

	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		ctx := context.Background()
		const cluster = "independent.proxy.example"
		yes, no := true, false

		require.NoError(t, store.SaveProxy(ctx, &proxy.Proxy{
			ID:             "proxy-independent",
			ClusterAddress: cluster,
			Status:         proxy.StatusConnected,
			LastSeen:       time.Now(),
			Capabilities: proxy.Capabilities{
				SupportsAppsec:   &yes,
				SupportsCrowdsec: &no,
			},
		}))

		appsec := store.GetClusterSupportsAppSec(ctx, cluster)
		crowdsec := store.GetClusterSupportsCrowdSec(ctx, cluster)
		require.NotNil(t, appsec)
		require.NotNil(t, crowdsec)
		assert.True(t, *appsec, "AppSec must not be gated on CrowdSec")
		assert.False(t, *crowdsec, "CrowdSec must not be implied by AppSec")
	})
}
