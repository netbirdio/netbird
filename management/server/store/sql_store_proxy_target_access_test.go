package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
)

func TestClusterSupportsTargetAccessControl(t *testing.T) {
	ctx := context.Background()
	testStore, cleanup, err := NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanup)

	const cluster = "proxy.example.com"
	assert.Nil(t, testStore.GetClusterSupportsTargetAccessControl(ctx, cluster),
		"an empty cluster must not advertise target access control")

	capable := true
	current := &proxy.Proxy{
		ID: "current", ClusterAddress: cluster, Status: proxy.StatusConnected,
		LastSeen:     time.Now(),
		Capabilities: proxy.Capabilities{SupportsTargetAccessControl: &capable},
	}
	require.NoError(t, testStore.SaveProxy(ctx, current))
	supported := testStore.GetClusterSupportsTargetAccessControl(ctx, cluster)
	require.NotNil(t, supported)
	assert.True(t, *supported, "a capable active proxy must enable the capability")

	legacy := &proxy.Proxy{
		ID: "legacy", ClusterAddress: cluster, Status: proxy.StatusConnected,
		LastSeen: time.Now(),
	}
	require.NoError(t, testStore.SaveProxy(ctx, legacy))
	supported = testStore.GetClusterSupportsTargetAccessControl(ctx, cluster)
	require.NotNil(t, supported)
	assert.False(t, *supported, "an active proxy with an unreported capability must veto support")

	incapable := false
	legacy.Capabilities.SupportsTargetAccessControl = &incapable
	require.NoError(t, testStore.SaveProxy(ctx, legacy))
	supported = testStore.GetClusterSupportsTargetAccessControl(ctx, cluster)
	require.NotNil(t, supported)
	assert.False(t, *supported, "an explicitly unsupported proxy must veto support")

	legacy.LastSeen = time.Now().Add(-3 * time.Minute)
	require.NoError(t, testStore.SaveProxy(ctx, legacy))
	supported = testStore.GetClusterSupportsTargetAccessControl(ctx, cluster)
	require.NotNil(t, supported)
	assert.True(t, *supported, "a stale proxy must not veto the active cluster capability")

	legacy.LastSeen = time.Now()
	legacy.Status = proxy.StatusDisconnected
	require.NoError(t, testStore.SaveProxy(ctx, legacy))
	supported = testStore.GetClusterSupportsTargetAccessControl(ctx, cluster)
	require.NotNil(t, supported)
	assert.True(t, *supported, "a disconnected proxy must not veto the active cluster capability")

	// A downgrade reconnect replaces a previous true report with NULL.
	current.Capabilities.SupportsTargetAccessControl = nil
	require.NoError(t, testStore.SaveProxy(ctx, current))
	assert.Nil(t, testStore.GetClusterSupportsTargetAccessControl(ctx, cluster),
		"reconnecting without capabilities must clear the previously reported capability")
}
