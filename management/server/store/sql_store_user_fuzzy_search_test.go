package store

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestXXX(t *testing.T) {
	b := newBloomFilter(160)
	for _, trigram := range toTrigrams("test user") {
		b.add([]byte(trigram))
	}
	for _, trigram := range toTrigrams("superduperuser") {
		b.add([]byte(trigram))
	}

	assert.True(t, b.test(toTrigrams("test user")))
	assert.True(t, b.test(toTrigrams("test")))
	assert.True(t, b.test(toTrigrams("user")))
	assert.True(t, b.test(toTrigrams("dup")))
	assert.True(t, b.test(toTrigrams("ruser")))
	assert.False(t, b.test(toTrigrams("not here")))
}

func TestSqlStore_SearchUsers(t *testing.T) {
	runTestForAllEnginesNoSqliteSeed(t, "../testdata/fuzzy_name_search.sql", func(t *testing.T, engine string, store Store) {
		var tests = []struct {
			description string
			pattern     string
			expectedLen int
		}{
			{
				pattern:     "hijklmntest-9995",
				expectedLen: 1,
			},
			{
				pattern:     "hijklmntest",
				expectedLen: 10000,
			},
			{
				pattern:     "xyzacegtest-20",
				expectedLen: 373,
			},
			{
				pattern:     "ser67",
				expectedLen: 36,
			},
			{
				pattern:     "user",
				expectedLen: 30000,
			},
		}

		for i := 0; i < 30000; i++ {
			var name string
			switch i % 9 {
			case 1, 3, 5:
				name = fmt.Sprintf("abcdefguser hijklmntest-%d", i)
			case 0, 2, 4:
				name = fmt.Sprintf("opqrstvuser xyzacegtest-%d", i)
			case 7, 6, 8:
				name = fmt.Sprintf("acegijluser%dxyzacetest", i)
			}
			b := newBloomFilter(160)
			for _, trigram := range toTrigrams(name) {
				b.add([]byte(trigram))
			}

			store.(*SqlStore).db.Exec(
				"insert into users (id,account_id,name,name_hash_1,name_hash_2,name_hash_3,name_hash_4,name_hash_5,name_hash_6) values(?,'account-1',?,?,?,?,?,?,?)",
				name, name, b.buckets[0], b.buckets[1], b.buckets[2], b.buckets[3], b.buckets[4], b.buckets[5])
		}

		for _, tt := range tests {
			t.Run(tt.description+" "+engine, func(t *testing.T) {
				t.Helper()
				b := newBloomFilter(160)
				for _, trigram := range toTrigrams(tt.pattern) {
					b.add([]byte(trigram))
				}

				users, err := store.GetAccountUsersPaginated(context.Background(), LockingStrengthNone, "account-1", tt.pattern)
				require.NoError(t, err)
				require.Len(t, users, tt.expectedLen)
			})
		}

		fmt.Print("aaaaaaaaaaaaaaaaaaaaa")
	})
}
