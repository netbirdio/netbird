package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSqlStore_FilterPeers_ByUserId(t *testing.T) {
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
				expectedLength: 1,
				expectedPeers:  []string{"peer-4-name"},
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
		}
		for _, tt := range tests {
			t.Run(tt.description+" "+engine, func(t *testing.T) {
				t.Helper()
				peers, _, err := store.GetAccountPeersPaginated(context.Background(), LockingStrengthNone, "account-1",
					PaginationState{}, tt.filters, PeerSorting{})
				require.NoError(t, err)
				require.Len(t, peers, tt.expectedLength)
				for i, ep := range tt.expectedPeers {
					require.Equal(t, peers[i].Name, ep)
				}
			})
		}
	})
}
