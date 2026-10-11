package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSqlStore_FilterPeers(t *testing.T) {
	runTestForAllEnginesNoSqliteSeed(t, "../testdata/peers_pagination.sql", func(t *testing.T, engine string, store Store) {
		var tests = []struct {
			description    string
			filters        PeerFilters
			expectedLength int
			expectedPeers  []string
		}{
			{
				description:    "filter by user_id",
				filters:        PeerFilters{UserId: "user-id-1"},
				expectedLength: 1,
				expectedPeers:  []string{"peer-1-name"},
			},
			{
				description:    "filter by connected status",
				filters:        PeerFilters{Connected: new(true)},
				expectedLength: 2,
				expectedPeers:  []string{"peer-1-name", "peer-2-name"},
			},
			{
				description:    "filter by approval required status",
				filters:        PeerFilters{ApprovalRequried: new(true)},
				expectedLength: 2,
				expectedPeers:  []string{"peer-2-name", "peer-3-name"},
			},
			{
				description:    "filter by ipv4",
				filters:        PeerFilters{IP: "10.10.10"},
				expectedLength: 2,
				expectedPeers:  []string{"peer-1-name", "peer-2-name"},
			},
			{
				description:    "filter by ipv6",
				filters:        PeerFilters{IP: "ba80:6aa5:89f1:44d7:8701:869"},
				expectedLength: 2,
				expectedPeers:  []string{"peer-2-name", "peer-3-name"},
			},
			{
				description:    "filter by mac",
				filters:        PeerFilters{MAC: ":15:5d:24:0c"},
				expectedLength: 3,
				expectedPeers:  []string{"peer-1-name", "peer-2-name", "peer-3-name"},
			},
			{
				description:    "filter by kind (server)",
				filters:        PeerFilters{IsServer: new(true)},
				expectedLength: 3,
				expectedPeers:  []string{"peer-4-name", "peer-5-name", "peer-6-name"},
			},
			{
				description:    "filter by kind (user_device)",
				filters:        PeerFilters{IsServer: new(false)},
				expectedLength: 3,
				expectedPeers:  []string{"peer-1-name", "peer-2-name", "peer-3-name"},
			},
			{
				description:    "filter by group_ids",
				filters:        PeerFilters{GroupIds: []string{"group-one-resource-id", "group-two-resources-id"}},
				expectedLength: 2,
				expectedPeers:  []string{"peer-1-name", "peer-2-name"},
			},
			{
				description:    "filter by os",
				filters:        PeerFilters{Os: []string{"linux", "ios"}},
				expectedLength: 5,
				expectedPeers:  []string{"peer-1-name", "peer-2-name", "peer-4-name", "peer-5-name", "peer-6-name"},
			},
		}
		for _, tt := range tests {
			t.Run(tt.description+" "+engine, func(t *testing.T) {
				t.Helper()
				peers, _, err := store.GetAccountPeersPaginated(context.Background(), LockingStrengthNone, "account-1",
					PaginationState{}, tt.filters, PeerSorting{})
				require.NoError(t, err)
				require.Len(t, peers, tt.expectedLength)
				actualPeerNames := make([]string, 0, len(peers))
				for _, p := range peers {
					actualPeerNames = append(actualPeerNames, p.Name)
				}
				require.ElementsMatch(t, actualPeerNames, tt.expectedPeers)
			})
		}
	})
}

func TestSqlStore_PeersPaging(t *testing.T) {
	runTestForAllEnginesNoSqliteSeed(t, "../testdata/peers_pagination.sql", func(t *testing.T, engine string, store Store) {
		var tests = []struct {
			description    string
			page           int
			pageSize       int
			expectedLength int
			expectedPeers  []string
		}{
			{
				description:    "page 0, size 4",
				page:           0,
				pageSize:       4,
				expectedLength: 4,
				expectedPeers:  []string{"peer-1-name", "peer-2-name", "peer-3-name", "peer-4-name"},
			},
			{
				description:    "page 1, size 4",
				page:           1,
				pageSize:       4,
				expectedLength: 2,
				expectedPeers:  []string{"peer-5-name", "peer-6-name"},
			},
		}
		for _, tt := range tests {
			t.Run(tt.description+" "+engine, func(t *testing.T) {
				t.Helper()
				peers, _, err := store.GetAccountPeersPaginated(context.Background(), LockingStrengthNone, "account-1",
					PaginationState{Page: tt.page, PageSize: tt.pageSize}, PeerFilters{}, PeerSorting{ByName: true})
				require.NoError(t, err)
				require.Len(t, peers, tt.expectedLength)
				actualPeerNames := make([]string, 0, len(peers))
				for _, p := range peers {
					actualPeerNames = append(actualPeerNames, p.Name)
				}
				require.ElementsMatch(t, actualPeerNames, tt.expectedPeers)
			})
		}
	})
}

func TestSqlStore_PeersSorting(t *testing.T) {
	runTestForAllEnginesNoSqliteSeed(t, "../testdata/peers_pagination.sql", func(t *testing.T, engine string, store Store) {
		var tests = []struct {
			description    string
			sorting        PeerSorting
			expectedLength int
			expectedPeers  []string
		}{
			{
				description:    "by name ascending",
				sorting:        PeerSorting{ByName: true},
				expectedLength: 6,
				expectedPeers:  []string{"peer-1-name", "peer-2-name", "peer-3-name", "peer-4-name", "peer-5-name", "peer-6-name"},
			},
			{
				description:    "by name descending",
				sorting:        PeerSorting{ByName: true, ByNameDescending: true},
				expectedLength: 6,
				expectedPeers:  []string{"peer-6-name", "peer-5-name", "peer-4-name", "peer-3-name", "peer-2-name", "peer-1-name"},
			},
			{
				description:    "by address ascending",
				sorting:        PeerSorting{ByAddress: true},
				expectedLength: 6,
				expectedPeers:  []string{"peer-1-name", "peer-2-name", "peer-4-name", "peer-3-name", "peer-6-name", "peer-5-name"},
			},
			{
				description:    "by address descending",
				sorting:        PeerSorting{ByAddress: true, ByAddressDescending: true},
				expectedLength: 6,
				expectedPeers:  []string{"peer-5-name", "peer-6-name", "peer-3-name", "peer-4-name", "peer-2-name", "peer-1-name"},
			},
			{
				description:    "by last_seen ascending",
				sorting:        PeerSorting{ByLastSeen: true},
				expectedLength: 6,
				expectedPeers:  []string{"peer-6-name", "peer-4-name", "peer-5-name", "peer-3-name", "peer-2-name", "peer-1-name"},
			},
			{
				description:    "by last_seen descending",
				sorting:        PeerSorting{ByLastSeen: true, ByLastSeenDescending: true},
				expectedLength: 6,
				expectedPeers:  []string{"peer-1-name", "peer-2-name", "peer-3-name", "peer-5-name", "peer-4-name", "peer-6-name"},
			},
			{
				description:    "by version ascending",
				sorting:        PeerSorting{ByVersion: true},
				expectedLength: 6,
				expectedPeers:  []string{"peer-1-name", "peer-2-name", "peer-4-name", "peer-3-name", "peer-6-name", "peer-5-name"},
			},
			{
				description:    "by version descending",
				sorting:        PeerSorting{ByVersion: true, ByVersionDescending: true},
				expectedLength: 6,
				expectedPeers:  []string{"peer-5-name", "peer-6-name", "peer-3-name", "peer-4-name", "peer-2-name", "peer-1-name"},
			},
		}
		for _, tt := range tests {
			t.Run(tt.description+" "+engine, func(t *testing.T) {
				t.Helper()
				peers, _, err := store.GetAccountPeersPaginated(context.Background(), LockingStrengthNone, "account-1",
					PaginationState{}, PeerFilters{}, tt.sorting)
				require.NoError(t, err)
				require.Len(t, peers, tt.expectedLength)
				actualPeerNames := make([]string, 0, len(peers))
				for _, p := range peers {
					actualPeerNames = append(actualPeerNames, p.Name)
				}
				require.Equal(t, tt.expectedPeers, actualPeerNames)
			})
		}
	})
}
