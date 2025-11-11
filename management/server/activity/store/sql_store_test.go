package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/testutil"
	"github.com/netbirdio/netbird/management/server/types"
)

var enginesToTest = []types.Engine{types.SqliteStoreEngine,types.PostgresStoreEngine,types.MysqlStoreEngine}

func runTestForAllEngines(t *testing.T, test func( t *testing.T, store *Store )) {
	dataDir := t.TempDir()
	key, _ := GenerateKey()
	
	for _,engine := range enginesToTest {
		t.Setenv("NB_ACTIVITY_EVENT_STORE_ENGINE",string(engine))
		switch engine {
		case types.PostgresStoreEngine :
			cleanup, dsn, err := testutil.CreatePostgresTestContainer()
			if err != nil {
				t.Fatalf("could not start Postgres container %s",err)
			}
			t.Cleanup(cleanup)
			t.Setenv("NB_ACTIVITY_EVENT_POSTGRES_DSN",dsn)
		case types.MysqlStoreEngine :
			cleanup, dsn, err := testutil.CreateMysqlTestContainer()
			if err != nil {
				t.Fatalf("could not start MySQL container %s",err)
			}
			t.Cleanup(cleanup)
			t.Setenv("NB_ACTIVITY_EVENT_MYSQL_DSN",dsn)
		default:
			t.Setenv("NB_ACTIVITY_EVENT_STORE_ENGINE",string(types.SqliteStoreEngine))

		}
		store, err := NewSqlStore(context.Background(), dataDir, key)
		if err != nil {
			t.Fatal(err)
			return
		}
		assert.NoError(t,err)
		t.Run(string(engine), func(t *testing.T) {
			test(t, store)
		})
	}

}

func TestNewSqlStore(t *testing.T) {

	runTestForAllEngines(t, func(t *testing.T, store *Store){
		defer store.Close(context.Background()) //nolint

		accountID := "account_1"

		for i := range 10 {
			_, err := store.Save(context.Background(), &activity.Event{
				Timestamp:   time.Now().UTC(),
				Activity:    activity.PeerAddedByUser,
				InitiatorID: "user_" + fmt.Sprint(i),
				TargetID:    "peer_" + fmt.Sprint(i),
				AccountID:   accountID,
			})
			if err != nil {
				t.Fatal(err)
				return
			}
		}

		result, err := store.Get(context.Background(), accountID, 0, 10, false)
		if err != nil {
			t.Fatal(err)
			return
		}

		assert.Len(t, result, 10)
		assert.True(t, result[0].Timestamp.Before(result[len(result)-1].Timestamp))

		result, err = store.Get(context.Background(), accountID, 0, 5, true)
		if err != nil {
			t.Fatal(err)
			return
		}

		assert.Len(t, result, 5)
		assert.True(t, result[0].Timestamp.After(result[len(result)-1].Timestamp))
	})
}
