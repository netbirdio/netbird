package settingoverrider

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	testcontainersredis "github.com/testcontainers/testcontainers-go/modules/redis"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestPoll_AppliesSettingFromRedis(t *testing.T) {
	o, client := setupOverrider(t)

	key := "test-setting-key"
	require.NoError(t, client.Set(context.Background(), key, "hello", 0).Err())

	var applied atomic.Value

	o.Poll(100*time.Millisecond, key, func(value string) error {
		applied.Store(value)
		return nil
	})

	assert.Eventually(t, func() bool {
		v := applied.Load()
		return v != nil && v.(string) == "hello"
	}, 5*time.Second, 50*time.Millisecond)
}

func TestPoll_IndependentSettings(t *testing.T) {
	o, client := setupOverrider(t)

	require.NoError(t, client.Set(context.Background(), "key-a", "val-a", 0).Err())
	require.NoError(t, client.Set(context.Background(), "key-b", "val-b", 0).Err())

	var gotA, gotB atomic.Value

	o.Poll(100*time.Millisecond, "key-a", func(v string) error { gotA.Store(v); return nil })
	o.Poll(100*time.Millisecond, "key-b", func(v string) error { gotB.Store(v); return nil })

	assert.Eventually(t, func() bool {
		a, b := gotA.Load(), gotB.Load()
		return a != nil && a.(string) == "val-a" && b != nil && b.(string) == "val-b"
	}, 5*time.Second, 50*time.Millisecond)
}

func TestPoll_SkipsDuplicateValues(t *testing.T) {
	o, client := setupOverrider(t)

	key := "test-dedup"
	require.NoError(t, client.Set(context.Background(), key, "same", 0).Err())

	var count atomic.Int32

	o.Poll(100*time.Millisecond, key, func(string) error {
		count.Add(1)
		return nil
	})

	// wait for a few ticks
	time.Sleep(600 * time.Millisecond)
	assert.Equal(t, int32(1), count.Load(), "Apply should be called only once for unchanged value")
}

func setupOverrider(t *testing.T) (*Overrider, *redis.Client) {
	t.Helper()

	ctx := context.Background()
	redisContainer, err := testcontainersredis.RunContainer(ctx,
		testcontainers.WithImage("redis:7"),
		testcontainers.WithWaitStrategy(
			wait.ForListeningPort("6379/tcp"),
		),
	)
	require.NoError(t, err, "Failed to create redis test container")

	t.Cleanup(func() {
		if err := redisContainer.Terminate(ctx); err != nil {
			t.Logf("failed to terminate redis container: %s", err)
		}
	})

	redisURL, err := redisContainer.ConnectionString(ctx)
	require.NoError(t, err)

	o, err := New(ctx, redisURL)
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := o.Close(); err != nil {
			t.Logf("failed to close overrider: %s", err)
		}
	})

	// separate client for test setup (setting keys)
	options, err := redis.ParseURL(redisURL)
	require.NoError(t, err)
	client := redis.NewClient(options)
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Logf("failed to close redis client: %s", err)
		}
	})

	return o, client
}
