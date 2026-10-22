package syncmapcache

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	testcontainersredis "github.com/testcontainers/testcontainers-go/modules/redis"
)

const (
	testGeneration = "gen-1"
	testKey        = KeyFingerprint("key-1")
)

func newTestClient(t *testing.T) *redis.Client {
	t.Helper()

	ctx := context.Background()
	container, err := testcontainersredis.Run(ctx, "redis:7")
	require.NoError(t, err, "redis container must start")
	t.Cleanup(func() {
		if err := container.Terminate(ctx); err != nil {
			t.Logf("failed to terminate redis container: %v", err)
		}
	})

	url, err := container.ConnectionString(ctx)
	require.NoError(t, err)
	opts, err := redis.ParseURL(url)
	require.NoError(t, err)

	client := redis.NewClient(opts)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// testClock is a settable clock, so the maximum age can be tested without sleeping.
type testClock struct{ t time.Time }

func (c *testClock) now() time.Time { return c.t }

func newTestCache(t *testing.T, client *redis.Client, clock *testClock) *Cache {
	t.Helper()
	c := New(client, Config{Enabled: true, Generation: testGeneration, MaxAge: time.Hour})
	if clock != nil {
		c.now = clock.now
	}
	return c
}

func TestCache(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	t.Run("an absent entry is not reusable", func(t *testing.T) {
		c := newTestCache(t, client, nil)
		l, err := c.Lookup(ctx, "absent", testKey)
		require.NoError(t, err)
		_, ok := l.Serial()
		assert.False(t, ok, "a peer without an entry must compute its map")
	})

	t.Run("a delivered map is reusable under the same generation and key", func(t *testing.T) {
		c := newTestCache(t, client, nil)
		peer := "delivered"
		seen, err := c.Lookup(ctx, peer, testKey)
		require.NoError(t, err)
		require.NoError(t, c.ClaimDelivered(ctx, peer, seen, 100, 7, testKey))

		l, err := c.Lookup(ctx, peer, testKey)
		require.NoError(t, err)
		serial, ok := l.Serial()
		assert.True(t, ok, "the entry must be reusable after a delivery")
		assert.Equal(t, uint64(7), serial, "the reusable serial must be the delivered one")
	})

	t.Run("another generation or key is not reusable", func(t *testing.T) {
		c := newTestCache(t, client, nil)
		peer := "generation"
		seen, err := c.Lookup(ctx, peer, testKey)
		require.NoError(t, err)
		require.NoError(t, c.ClaimDelivered(ctx, peer, seen, 100, 7, testKey))

		l, err := c.Lookup(ctx, peer, "key-2")
		require.NoError(t, err)
		_, ok := l.Serial()
		assert.False(t, ok, "a map encrypted for another management key must not be reused")

		other := New(client, Config{Enabled: true, Generation: "gen-2", MaxAge: time.Hour})
		l, err = other.Lookup(ctx, peer, testKey)
		require.NoError(t, err)
		_, ok = l.Serial()
		assert.False(t, ok, "a map built by another generation must not be reused")
	})

	t.Run("an entry older than the maximum age is not reusable", func(t *testing.T) {
		clock := &testClock{t: time.Unix(1_000_000, 0)}
		c := newTestCache(t, client, clock)
		peer := "aged"
		seen, err := c.Lookup(ctx, peer, testKey)
		require.NoError(t, err)
		require.NoError(t, c.ClaimDelivered(ctx, peer, seen, 100, 7, testKey))

		// A reuse hands the entry over but does not count as a delivery, so it must
		// not extend the age.
		clock.t = clock.t.Add(30 * time.Minute)
		seen, err = c.Lookup(ctx, peer, testKey)
		require.NoError(t, err)
		require.NoError(t, c.ClaimReused(ctx, peer, seen, 200, testKey))

		clock.t = clock.t.Add(31 * time.Minute)
		l, err := c.Lookup(ctx, peer, testKey)
		require.NoError(t, err)
		_, ok := l.Serial()
		assert.False(t, ok, "an entry past the maximum age since its last delivery must not be reused")
	})

	t.Run("a login between lookup and claim wins", func(t *testing.T) {
		c := newTestCache(t, client, nil)
		peer := "login-race"
		seen, err := c.Lookup(ctx, peer, testKey)
		require.NoError(t, err)

		// The previous engine's Sync read the entry, then the new engine logged in.
		require.NoError(t, c.OnLogin(ctx, peer))
		require.NoError(t, c.ClaimDelivered(ctx, peer, seen, 100, 7, testKey))

		l, err := c.Lookup(ctx, peer, testKey)
		require.NoError(t, err)
		_, ok := l.Serial()
		assert.False(t, ok, "a stream that started before a login must not vouch for the new engine")
	})

	t.Run("login invalidates a delivered map", func(t *testing.T) {
		c := newTestCache(t, client, nil)
		peer := "login"
		seen, err := c.Lookup(ctx, peer, testKey)
		require.NoError(t, err)
		require.NoError(t, c.ClaimDelivered(ctx, peer, seen, 100, 7, testKey))
		require.NoError(t, c.OnLogin(ctx, peer))

		l, err := c.Lookup(ctx, peer, testKey)
		require.NoError(t, err)
		_, ok := l.Serial()
		assert.False(t, ok, "a new engine after login must compute its map")

		// The stream that owned the entry before the login must not bring it back.
		require.NoError(t, c.Advance(ctx, peer, 100, 8))
		l, err = c.Lookup(ctx, peer, testKey)
		require.NoError(t, err)
		_, ok = l.Serial()
		assert.False(t, ok, "an old stream must not advance an entry after login")
	})

	t.Run("only the owning stream advances, and never backwards", func(t *testing.T) {
		c := newTestCache(t, client, nil)
		peer := "advance"
		seen, err := c.Lookup(ctx, peer, testKey)
		require.NoError(t, err)
		require.NoError(t, c.ClaimDelivered(ctx, peer, seen, 100, 7, testKey))

		require.NoError(t, c.Advance(ctx, peer, 99, 9))
		require.NoError(t, c.Advance(ctx, peer, 100, 8))
		require.NoError(t, c.Advance(ctx, peer, 100, 6))

		l, err := c.Lookup(ctx, peer, testKey)
		require.NoError(t, err)
		serial, ok := l.Serial()
		require.True(t, ok)
		assert.Equal(t, uint64(8), serial, "only the owner's highest delivered serial must be recorded")
	})

	t.Run("invalidating a session spares a newer owner", func(t *testing.T) {
		c := newTestCache(t, client, nil)
		peer := "session"
		seen, err := c.Lookup(ctx, peer, testKey)
		require.NoError(t, err)
		require.NoError(t, c.ClaimDelivered(ctx, peer, seen, 100, 7, testKey))
		seen, err = c.Lookup(ctx, peer, testKey)
		require.NoError(t, err)
		require.NoError(t, c.ClaimDelivered(ctx, peer, seen, 200, 7, testKey))

		require.NoError(t, c.InvalidateSession(ctx, peer, 100))
		l, err := c.Lookup(ctx, peer, testKey)
		require.NoError(t, err)
		_, ok := l.Serial()
		assert.True(t, ok, "the end of a superseded stream must not invalidate its successor")

		require.NoError(t, c.InvalidateSession(ctx, peer, 200))
		l, err = c.Lookup(ctx, peer, testKey)
		require.NoError(t, err)
		_, ok = l.Serial()
		assert.False(t, ok, "the end of the owning stream must invalidate the entry")
	})

	t.Run("an invalidated stream cannot advance again", func(t *testing.T) {
		c := newTestCache(t, client, nil)
		peer := "poisoned"
		seen, err := c.Lookup(ctx, peer, testKey)
		require.NoError(t, err)
		require.NoError(t, c.ClaimDelivered(ctx, peer, seen, 100, 7, testKey))

		// A dropped update invalidates the entry; later deliveries on the same stream
		// may predate what was dropped, so they must not make it reusable again.
		require.NoError(t, c.Invalidate(ctx, peer))
		require.NoError(t, c.Advance(ctx, peer, 100, 8))

		l, err := c.Lookup(ctx, peer, testKey)
		require.NoError(t, err)
		_, ok := l.Serial()
		assert.False(t, ok, "a stream that lost an update must not make the entry reusable")
	})

	t.Run("a reuse claim loses to any change since the lookup", func(t *testing.T) {
		c := newTestCache(t, client, nil)
		peer := "reuse-race"
		seen, err := c.Lookup(ctx, peer, testKey)
		require.NoError(t, err)
		require.NoError(t, c.ClaimDelivered(ctx, peer, seen, 100, 7, testKey))

		seen, err = c.Lookup(ctx, peer, testKey)
		require.NoError(t, err)
		require.NoError(t, c.Invalidate(ctx, peer))
		require.NoError(t, c.ClaimReused(ctx, peer, seen, 200, testKey))

		l, err := c.Lookup(ctx, peer, testKey)
		require.NoError(t, err)
		_, ok := l.Serial()
		assert.False(t, ok, "a reuse must not revive an entry invalidated after its lookup")
	})

	t.Run("a reuse claim hands the entry to the new stream", func(t *testing.T) {
		c := newTestCache(t, client, nil)
		peer := "reuse"
		seen, err := c.Lookup(ctx, peer, testKey)
		require.NoError(t, err)
		require.NoError(t, c.ClaimDelivered(ctx, peer, seen, 100, 7, testKey))

		seen, err = c.Lookup(ctx, peer, testKey)
		require.NoError(t, err)
		require.NoError(t, c.ClaimReused(ctx, peer, seen, 200, testKey))

		require.NoError(t, c.Advance(ctx, peer, 100, 9))
		require.NoError(t, c.Advance(ctx, peer, 200, 8))
		l, err := c.Lookup(ctx, peer, testKey)
		require.NoError(t, err)
		serial, ok := l.Serial()
		require.True(t, ok)
		assert.Equal(t, uint64(8), serial, "after a reuse only the new stream may advance the entry")
	})
}

func TestCacheRedisErrors(t *testing.T) {
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 100 * time.Millisecond, MaxRetries: -1})
	t.Cleanup(func() { _ = client.Close() })
	c := New(client, Config{Enabled: true, Generation: testGeneration})
	ctx := context.Background()

	_, err := c.Lookup(ctx, "peer", testKey)
	assert.Error(t, err, "an unreachable Redis must surface as an error so Sync computes the map")
	assert.Error(t, c.OnLogin(ctx, "peer"), "an unreachable Redis must fail the login invalidation")
}

func TestConfigFromEnv(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		t.Setenv(EnvEnabled, "")
		t.Setenv(EnvMaxAge, "")
		t.Setenv(EnvResyncWindow, "")
		cfg := ConfigFromEnv("g")
		assert.False(t, cfg.Enabled, "the cache must be off unless enabled")
		assert.Equal(t, defaultMaxAge, cfg.MaxAge, "max age default")
		assert.Equal(t, defaultResyncWindow, cfg.ResyncWindow, "resync window default")
		assert.Equal(t, "g", cfg.Generation, "generation must be passed through")
	})

	t.Run("explicit values", func(t *testing.T) {
		t.Setenv(EnvEnabled, "true")
		t.Setenv(EnvMaxAge, "3h")
		t.Setenv(EnvResyncWindow, "0")
		cfg := ConfigFromEnv("g")
		assert.True(t, cfg.Enabled, "enabled flag")
		assert.Equal(t, 3*time.Hour, cfg.MaxAge, "max age")
		assert.Equal(t, time.Duration(0), cfg.ResyncWindow, "a zero resync window disables the push")
	})

	t.Run("invalid values fall back", func(t *testing.T) {
		t.Setenv(EnvEnabled, "maybe")
		t.Setenv(EnvMaxAge, "0")
		t.Setenv(EnvResyncWindow, "-1m")
		cfg := ConfigFromEnv("g")
		assert.False(t, cfg.Enabled, "an unparseable flag must leave the cache off")
		assert.Equal(t, defaultMaxAge, cfg.MaxAge, "a zero max age must fall back to the default")
		assert.Equal(t, defaultResyncWindow, cfg.ResyncWindow, "a negative window must fall back to the default")
	})
}
