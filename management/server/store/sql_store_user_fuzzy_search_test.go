package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSqlStore_SearchUsers(t *testing.T) {
	runTestForAllEnginesNoSqliteSeed(t, "../testdata/fuzzy_name_search.sql", func(t *testing.T, engine string, store Store) {
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
				expectedPeers:  []string{"Peer-1-name"},
			},
		}
		for _, tt := range tests {
			t.Run(tt.description+" "+engine, func(t *testing.T) {
				t.Helper()
				b := newBloomFilter(160)
				for _, trigram := range toTrigrams("test user") {
					b.add([]byte(trigram))
				}
				r := b.test(toTrigrams("test user"))
				assert.True(t, r)
				r = b.test(toTrigrams("test"))
				assert.True(t, r)
				r = b.test(toTrigrams("user"))
				assert.True(t, r)
				r = b.test(toTrigrams("st us"))
				assert.True(t, r)

				store.(*SqlStore).db.Exec(
					"insert into users (id,account_id,name_hash_1,name_hash_2,name_hash_3,name_hash_4,name_hash_5) values('user-1','account-1',?,?,?,?,?)",
					b.buckets[0], b.buckets[1], b.buckets[2], b.buckets[3], b.buckets[4])
				users, err := store.GetAccountUsersPaginated(context.Background(), LockingStrengthNone, "account-1", "st use")
				require.Len(t, users, 1)
				require.NoError(t, err)
			})
		}
	})
}
