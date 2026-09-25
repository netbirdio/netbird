package store

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	nbroute "github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/status"
)

func TestSqlStore_GetAccountRoutes(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	tests := []struct {
		name          string
		accountID     string
		expectedCount int
	}{
		{
			name:          "retrieve routes by existing account ID",
			accountID:     "bf1c8084-ba50-4ce7-9439-34653001fc3b",
			expectedCount: 1,
		},
		{
			name:          "non-existing account ID",
			accountID:     "nonexistent",
			expectedCount: 0,
		},
		{
			name:          "empty account ID",
			accountID:     "",
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			routes, err := store.GetAccountRoutes(context.Background(), LockingStrengthNone, tt.accountID)
			require.NoError(t, err)
			require.Len(t, routes, tt.expectedCount)
		})
	}
}

func TestSqlStore_GetRouteByID(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	tests := []struct {
		name        string
		routeID     string
		expectError bool
	}{
		{
			name:        "retrieve existing route",
			routeID:     "ct03t427qv97vmtmglog",
			expectError: false,
		},
		{
			name:        "retrieve non-existing route",
			routeID:     "non-existing",
			expectError: true,
		},
		{
			name:        "retrieve with empty route ID",
			routeID:     "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route, err := store.GetRouteByID(context.Background(), LockingStrengthNone, accountID, tt.routeID)
			if tt.expectError {
				require.Error(t, err)
				sErr, ok := status.FromError(err)
				require.True(t, ok)
				require.Equal(t, sErr.Type(), status.NotFound)
				require.Nil(t, route)
			} else {
				require.NoError(t, err)
				require.NotNil(t, route)
				require.Equal(t, tt.routeID, string(route.ID))
			}
		})
	}
}

func TestSqlStore_GetRouteByIDOrPublicID(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	routeID := "ct03t427qv97vmtmglog"

	route, err := store.GetRouteByID(context.Background(), LockingStrengthNone, accountID, routeID)
	require.NoError(t, err)
	require.NotEmpty(t, route.PublicID)

	for _, id := range []string{routeID, route.PublicID} {
		route, err := store.GetRouteByIDOrPublicID(context.Background(), LockingStrengthNone, accountID, id)
		require.NoError(t, err)
		require.Equal(t, routeID, string(route.ID))
	}

	route, err = store.GetRouteByIDOrPublicID(context.Background(), LockingStrengthNone, accountID, "non-existing")
	require.Error(t, err)
	sErr, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, sErr.Type(), status.NotFound)
	require.Nil(t, route)
}

func TestSqlStore_SaveRoute(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	route := &nbroute.Route{
		ID:                  "route-id",
		AccountID:           accountID,
		Network:             netip.MustParsePrefix("10.10.0.0/16"),
		NetID:               "netID",
		PeerGroups:          []string{"routeA"},
		NetworkType:         nbroute.IPv4Network,
		Masquerade:          true,
		Metric:              9999,
		Enabled:             true,
		Groups:              []string{"groupA"},
		AccessControlGroups: []string{},
	}
	err = store.SaveRoute(context.Background(), route)
	require.NoError(t, err)

	saveRoute, err := store.GetRouteByID(context.Background(), LockingStrengthNone, accountID, string(route.ID))
	require.NoError(t, err)
	require.Equal(t, route, saveRoute)

}

func TestSqlStore_DeleteRoute(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	routeID := "ct03t427qv97vmtmglog"

	err = store.DeleteRoute(context.Background(), accountID, routeID)
	require.NoError(t, err)

	route, err := store.GetRouteByID(context.Background(), LockingStrengthNone, accountID, routeID)
	require.Error(t, err)
	require.Nil(t, route)
}
