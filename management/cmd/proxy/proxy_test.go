package proxycmd

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	rpproxy "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	"github.com/netbirdio/netbird/management/server/store"
)

func newTestStore(t *testing.T) store.Store {
	t.Helper()

	s, cleanup, err := store.NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanup)

	return s
}

func seedProxies(t *testing.T, ctx context.Context, s store.Store) {
	t.Helper()

	accountID := "account-1"
	alreadyDisconnectedAt := time.Now().Add(-time.Hour)
	seed := []*rpproxy.Proxy{
		{
			ID:             "proxy-1",
			SessionID:      "session-1",
			ClusterAddress: "cluster-a.example.com",
			IPAddress:      "10.0.0.1",
			LastSeen:       time.Now(),
			Status:         rpproxy.StatusConnected,
		},
		{
			ID:             "proxy-2",
			SessionID:      "session-2",
			ClusterAddress: "cluster-b.example.com",
			IPAddress:      "10.0.0.2",
			AccountID:      &accountID,
			LastSeen:       time.Now(),
			Status:         rpproxy.StatusConnected,
		},
		{
			ID:             "proxy-3",
			SessionID:      "session-3",
			ClusterAddress: "cluster-a.example.com",
			IPAddress:      "10.0.0.3",
			LastSeen:       time.Now().Add(-time.Hour),
			Status:         rpproxy.StatusDisconnected,
			DisconnectedAt: &alreadyDisconnectedAt,
		},
	}
	for _, p := range seed {
		require.NoError(t, s.SaveProxy(ctx, p))
	}
}

func proxiesByID(t *testing.T, ctx context.Context, s store.Store) map[string]*rpproxy.Proxy {
	t.Helper()

	proxies, err := s.GetAllProxies(ctx)
	require.NoError(t, err)
	require.Len(t, proxies, 3)

	byID := make(map[string]*rpproxy.Proxy, len(proxies))
	for _, p := range proxies {
		byID[p.ID] = p
	}
	return byID
}

func TestRunDisconnectAllWithConfirmation(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedProxies(t, ctx, s)

	var out bytes.Buffer
	require.NoError(t, runDisconnectAll(ctx, s, &out, strings.NewReader(disconnectAllConfirmation+"\n"), false, false))

	output := out.String()
	require.Contains(t, output, "proxy-1")
	require.Contains(t, output, "proxy-2")
	require.Contains(t, output, "proxy-3")
	require.Contains(t, output, "cluster-a.example.com")
	require.Contains(t, output, "account-1")
	require.Contains(t, output, "Type \"disconnect all proxies\" to continue")
	require.Contains(t, output, "Force-marked 2 of 3 reverse proxy instance(s) as disconnected.")

	for _, p := range proxiesByID(t, ctx, s) {
		require.Equal(t, rpproxy.StatusDisconnected, p.Status, "proxy %s should be disconnected", p.ID)
		require.NotNil(t, p.DisconnectedAt, "proxy %s should have a disconnected timestamp", p.ID)
	}
}

func TestRunDisconnectAllForceSkipsConfirmation(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedProxies(t, ctx, s)

	var out bytes.Buffer
	require.NoError(t, runDisconnectAll(ctx, s, &out, strings.NewReader(""), false, true))

	output := out.String()
	require.NotContains(t, output, "Type \"disconnect all proxies\" to continue")
	require.Contains(t, output, "Force-marked 2 of 3 reverse proxy instance(s) as disconnected.")
}

func TestRunDisconnectAllAbortLeavesProxiesUnchanged(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedProxies(t, ctx, s)

	var out bytes.Buffer
	require.NoError(t, runDisconnectAll(ctx, s, &out, strings.NewReader("no\n"), false, false))

	output := out.String()
	require.Contains(t, output, "Type \"disconnect all proxies\" to continue")
	require.Contains(t, output, "Aborted. No reverse proxy instances were changed.")

	byID := proxiesByID(t, ctx, s)
	require.Equal(t, rpproxy.StatusConnected, byID["proxy-1"].Status)
	require.Equal(t, rpproxy.StatusConnected, byID["proxy-2"].Status)
	require.Equal(t, rpproxy.StatusDisconnected, byID["proxy-3"].Status)
}

func TestRunDisconnectAllDryRunLeavesProxiesUnchanged(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedProxies(t, ctx, s)

	var out bytes.Buffer
	require.NoError(t, runDisconnectAll(ctx, s, &out, strings.NewReader(""), true, false))

	output := out.String()
	require.Contains(t, output, "Dry run: would force-mark 2 of 3 reverse proxy instance(s) as disconnected.")
	require.NotContains(t, output, "Type \"disconnect all proxies\" to continue")

	byID := proxiesByID(t, ctx, s)
	require.Equal(t, rpproxy.StatusConnected, byID["proxy-1"].Status)
	require.Equal(t, rpproxy.StatusConnected, byID["proxy-2"].Status)
	require.Equal(t, rpproxy.StatusDisconnected, byID["proxy-3"].Status)
}

func TestNewCommandsDisconnectAllDryRun(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	seedProxies(t, ctx, s)

	opened := false
	cmd := NewCommands(func(cmd *cobra.Command, fn func(ctx context.Context, s store.Store) error) error {
		opened = true
		return fn(cmd.Context(), s)
	})

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetIn(strings.NewReader(""))
	cmd.SetArgs([]string{"disconnect-all", "--dry-run"})

	require.NoError(t, cmd.ExecuteContext(ctx))
	require.True(t, opened)
	require.Contains(t, out.String(), "Dry run: would force-mark 2 of 3 reverse proxy instance(s) as disconnected.")
}

func TestRunDisconnectAllEmpty(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	var out bytes.Buffer
	require.NoError(t, runDisconnectAll(ctx, s, &out, strings.NewReader(""), false, false))
	require.Contains(t, out.String(), "No reverse proxy instances found.")
}
