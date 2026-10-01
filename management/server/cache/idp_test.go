package cache_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/eko/gocache/lib/v4/store"
	"github.com/redis/go-redis/v9"
	"github.com/vmihailenco/msgpack/v5"

	"github.com/netbirdio/netbird/management/server/cache"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/testutil"
)

func TestNewIDPCacheManagers(t *testing.T) {
	tt := []struct {
		name  string
		redis bool
	}{
		{"memory", false},
		{"redis", true},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			if tc.redis {
				cleanup, redisURL, err := testutil.CreateRedisTestContainer()
				if err != nil {
					t.Fatalf("couldn't start redis container: %s", err)
				}
				t.Cleanup(cleanup)
				t.Setenv(cache.RedisStoreEnvVar, redisURL)
			}
			cacheStore, err := cache.NewStore(context.Background(), cache.DefaultIDPCacheExpirationMax, cache.DefaultIDPCacheCleanupInterval, cache.DefaultIDPCacheOpenConn)
			if err != nil {
				t.Fatalf("couldn't create cache store: %s", err)
			}

			simple := cache.NewUserDataCache(cacheStore)
			loadable := cache.NewAccountUserDataCache(loader, cacheStore)

			ctx := context.Background()
			value := &idp.UserData{ID: "v", Name: "vv"}
			err = simple.Set(ctx, "key1", value, time.Minute)
			if err != nil {
				t.Errorf("couldn't set testing data: %s", err)
			}

			result, err := simple.Get(ctx, "key1")
			if err != nil {
				t.Errorf("couldn't get testing data: %s", err)
			}
			if value.ID != result.ID || value.Name != result.Name {
				t.Errorf("value returned doesn't match testing data, got %v, expected %v", result, "value1")
			}
			values := []*idp.UserData{
				{ID: "v2", Name: "v2v2"},
				{ID: "v3", Name: "v3v3"},
				{ID: "v4", Name: "v4v4"},
			}
			err = loadable.Set(ctx, "key2", values, time.Minute)

			if err != nil {
				t.Errorf("couldn't set testing data: %s", err)
			}
			result2, err := loadable.Get(ctx, "key2")
			if err != nil {
				t.Errorf("couldn't get testing data: %s", err)
			}

			if values[0].ID != result2[0].ID || values[0].Name != result2[0].Name {
				t.Errorf("value returned doesn't match testing data, got %v, expected %v", result2[0], values[0])
			}
			if values[1].ID != result2[1].ID || values[1].Name != result2[1].Name {
				t.Errorf("value returned doesn't match testing data, got %v, expected %v", result2[1], values[1])
			}

			// checking with direct store client
			if tc.redis {
				// wait for redis to sync
				options, err := redis.ParseURL(os.Getenv(cache.RedisStoreEnvVar))
				if err != nil {
					t.Fatalf("parsing redis cache url: %s", err)
				}

				redisClient := redis.NewClient(options)
				_, err = redisClient.Get(ctx, "loadKey").Result()
				if err == nil {
					t.Errorf("shouldn't find testing data from redis")
				}
			}

			// testing loadable capability
			result2, err = loadable.Get(ctx, "loadKey")
			if err != nil {
				t.Errorf("couldn't get testing data: %s", err)
			}

			if loadData[0].ID != result2[0].ID || loadData[0].Name != result2[0].Name {
				t.Errorf("value returned doesn't match testing data, got %v, expected %v", result2[0], loadData[0])
			}
			if loadData[1].ID != result2[1].ID || loadData[1].Name != result2[1].Name {
				t.Errorf("value returned doesn't match testing data, got %v, expected %v", result2[1], loadData[1])
			}
		})
	}

}

var loadData = []*idp.UserData{
	{ID: "a", Name: "aa"},
	{ID: "b", Name: "bb"},
	{ID: "c", Name: "cc"},
}

func loader(ctx context.Context, key any) (any, []store.Option, error) {
	bytes, err := msgpack.Marshal(loadData)
	if err != nil {
		return nil, nil, err
	}
	return bytes, nil, nil
}
