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

// testClock is a settable clock, so ages and the release grace can be tested
// without sleeping.
type testClock struct{ t time.Time }

func (c *testClock) now() time.Time { return c.t }

func (c *testClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// testInstance is one management process: its own cache, clock and shutdown state
// over the shared Redis.
type testInstance struct {
	*Cache
	clock *testClock
}

func newInstance(client *redis.Client, generation string) *testInstance {
	clock := &testClock{t: time.Unix(1_000_000, 0)}
	c := New(client, Config{Enabled: true, Generation: generation, MaxAge: time.Hour})
	c.now = clock.now
	return &testInstance{Cache: c, clock: clock}
}

// deliver runs the write side of a Sync that computed and sent a full map.
func (i *testInstance) deliver(t *testing.T, peer PeerKey, session Session, serial uint64) {
	t.Helper()
	seen, err := i.Lookup(context.Background(), peer, testKey)
	require.NoError(t, err)
	require.NoError(t, i.ClaimDelivered(context.Background(), peer, seen, session, serial, testKey))
}

// restart shuts the instance down and releases the stream's entry the way a
// stream ended by the shutdown does.
func (i *testInstance) restart(t *testing.T, peer PeerKey, session Session, lastSent time.Time) {
	t.Helper()
	i.clock.advance(time.Minute)
	i.BeginShutdown()
	require.NoError(t, i.Release(context.Background(), peer, session, lastSent))
}

func (i *testInstance) reusable(t *testing.T, peer PeerKey) (uint64, bool) {
	t.Helper()
	l, err := i.Lookup(context.Background(), peer, testKey)
	require.NoError(t, err)
	return l.Serial()
}

func TestCache(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	t.Run("an absent entry is not reusable", func(t *testing.T) {
		_, ok := newInstance(client, testGeneration).reusable(t, "absent")
		assert.False(t, ok, "a peer without an entry must compute its map")
	})

	t.Run("an entry whose stream is still open is not reusable", func(t *testing.T) {
		i := newInstance(client, testGeneration)
		i.deliver(t, "open", 100, 7)
		_, ok := i.reusable(t, "open")
		assert.False(t, ok, "a stream the server still considers open may be dead behind a proxy")
	})

	t.Run("an entry released at shutdown is reusable on the next instance", func(t *testing.T) {
		old := newInstance(client, testGeneration)
		old.deliver(t, "released", 100, 7)
		old.restart(t, "released", 100, old.clock.t)

		serial, ok := newInstance(client, testGeneration).reusable(t, "released")
		assert.True(t, ok, "the entry must be reusable after its stream was ended by the shutdown")
		assert.Equal(t, uint64(7), serial, "the reusable serial must be the delivered one")
	})

	t.Run("a map sent right before the shutdown is not released", func(t *testing.T) {
		old := newInstance(client, testGeneration)
		old.deliver(t, "late", 100, 7)
		old.clock.advance(time.Minute)
		lastSent := old.clock.t
		old.BeginShutdown()
		require.NoError(t, old.Release(ctx, "late", 100, lastSent))

		_, ok := newInstance(client, testGeneration).reusable(t, "late")
		assert.False(t, ok, "frames still being flushed when the server stops may never reach the client")
	})

	t.Run("release requires a shutdown and the owning stream", func(t *testing.T) {
		i := newInstance(client, testGeneration)
		i.deliver(t, "owner", 100, 7)
		assert.Error(t, i.Release(ctx, "owner", 100, time.Time{}), "a running server must not release entries")

		i.clock.advance(time.Minute)
		i.BeginShutdown()
		require.NoError(t, i.Release(ctx, "owner", 99, time.Time{}))
		_, ok := newInstance(client, testGeneration).reusable(t, "owner")
		assert.False(t, ok, "a superseded stream must not release its successor's entry")
	})

	t.Run("another generation or key is not reusable", func(t *testing.T) {
		old := newInstance(client, testGeneration)
		old.deliver(t, "generation", 100, 7)
		old.restart(t, "generation", 100, time.Time{})

		next := newInstance(client, testGeneration)
		l, err := next.Lookup(ctx, "generation", "key-2")
		require.NoError(t, err)
		_, ok := l.Serial()
		assert.False(t, ok, "a map encrypted for another management key must not be reused")

		_, ok = newInstance(client, "gen-2").reusable(t, "generation")
		assert.False(t, ok, "a map built by another generation must not be reused")
	})

	t.Run("an entry older than the maximum age is not reusable", func(t *testing.T) {
		old := newInstance(client, testGeneration)
		old.deliver(t, "aged", 100, 7)
		old.restart(t, "aged", 100, time.Time{})

		next := newInstance(client, testGeneration)
		next.clock.t = old.clock.t.Add(61 * time.Minute)
		_, ok := next.reusable(t, "aged")
		assert.False(t, ok, "an entry past the maximum age since its last delivery must not be reused")
	})

	t.Run("a delivery time from a clock far ahead is not trusted", func(t *testing.T) {
		old := newInstance(client, testGeneration)
		old.clock.t = old.clock.t.Add(30 * 24 * time.Hour)
		old.deliver(t, "skewed", 100, 7)
		old.restart(t, "skewed", 100, time.Time{})

		_, ok := newInstance(client, testGeneration).reusable(t, "skewed")
		assert.False(t, ok, "a delivery time in the future would disable the maximum age")
	})

	t.Run("a reuse claim does not count as a delivery", func(t *testing.T) {
		old := newInstance(client, testGeneration)
		old.deliver(t, "reused-age", 100, 7)
		old.restart(t, "reused-age", 100, time.Time{})

		// The next instance reuses the map half an hour later and is restarted in turn.
		next := newInstance(client, testGeneration)
		next.clock.t = old.clock.t.Add(30 * time.Minute)
		seen, err := next.Lookup(ctx, "reused-age", testKey)
		require.NoError(t, err)
		require.NoError(t, next.ClaimReused(ctx, "reused-age", seen, 200, testKey))
		next.restart(t, "reused-age", 200, time.Time{})

		third := newInstance(client, testGeneration)
		third.clock.t = old.clock.t.Add(61 * time.Minute)
		_, ok := third.reusable(t, "reused-age")
		assert.False(t, ok, "the maximum age must count from the last map actually sent")
	})

	t.Run("a login between lookup and claim wins", func(t *testing.T) {
		i := newInstance(client, testGeneration)
		i.deliver(t, "login-race", 100, 7)
		seen, err := i.Lookup(ctx, "login-race", testKey)
		require.NoError(t, err)

		// The previous engine's Sync read the entry, then the new engine logged in.
		require.NoError(t, i.OnLogin(ctx, "login-race"))
		err = i.ClaimDelivered(ctx, "login-race", seen, 200, 7, testKey)
		assert.ErrorIs(t, err, ErrClaimLost, "a stream that read the entry before a login must lose its claim")
	})

	t.Run("login invalidates a released map", func(t *testing.T) {
		old := newInstance(client, testGeneration)
		old.deliver(t, "login", 100, 7)
		old.restart(t, "login", 100, time.Time{})

		next := newInstance(client, testGeneration)
		require.NoError(t, next.OnLogin(ctx, "login"))
		_, ok := next.reusable(t, "login")
		assert.False(t, ok, "a new engine after login must compute its map")
	})

	t.Run("login does not create entries", func(t *testing.T) {
		i := newInstance(client, testGeneration)
		require.NoError(t, i.OnLogin(ctx, "unknown"))
		exists, err := client.Exists(ctx, entryKey("unknown")).Result()
		require.NoError(t, err)
		assert.Zero(t, exists, "an unauthenticated login must not leave a key behind")
	})

	t.Run("only the owning stream advances, never backwards", func(t *testing.T) {
		i := newInstance(client, testGeneration)
		i.deliver(t, "advance", 100, 7)

		applied, err := i.Advance(ctx, "advance", 99, 9)
		require.NoError(t, err)
		assert.False(t, applied, "another stream must not advance the entry")
		applied, err = i.Advance(ctx, "advance", 100, 8)
		require.NoError(t, err)
		assert.True(t, applied, "the owning stream advances the entry")
		_, err = i.Advance(ctx, "advance", 100, 6)
		require.NoError(t, err)

		i.restart(t, "advance", 100, time.Time{})
		serial, ok := newInstance(client, testGeneration).reusable(t, "advance")
		require.True(t, ok, "the released entry must be reusable")
		assert.Equal(t, uint64(8), serial, "only the owner's highest sent serial must be recorded")
	})

	t.Run("an invalidated stream cannot advance or release again", func(t *testing.T) {
		i := newInstance(client, testGeneration)
		i.deliver(t, "poisoned", 100, 7)

		// A dropped update invalidates the entry; later sends on the same stream may
		// predate what was dropped, so they must not make it reusable again.
		require.NoError(t, i.Invalidate(ctx, "poisoned"))
		applied, err := i.Advance(ctx, "poisoned", 100, 8)
		require.NoError(t, err)
		assert.False(t, applied, "an invalidated stream no longer owns the entry")
		i.restart(t, "poisoned", 100, time.Time{})

		_, ok := newInstance(client, testGeneration).reusable(t, "poisoned")
		assert.False(t, ok, "a stream that lost an update must not make the entry reusable")
	})

	t.Run("a reuse claim loses to any change since the lookup", func(t *testing.T) {
		old := newInstance(client, testGeneration)
		old.deliver(t, "reuse-race", 100, 7)
		old.restart(t, "reuse-race", 100, time.Time{})

		next := newInstance(client, testGeneration)
		seen, err := next.Lookup(ctx, "reuse-race", testKey)
		require.NoError(t, err)
		require.NoError(t, next.Invalidate(ctx, "reuse-race"))
		assert.ErrorIs(t, next.ClaimReused(ctx, "reuse-race", seen, 200, testKey), ErrClaimLost,
			"a reuse must not revive an entry invalidated after its lookup")
	})

	t.Run("a reuse claim hands the entry to the new stream", func(t *testing.T) {
		old := newInstance(client, testGeneration)
		old.deliver(t, "reuse", 100, 7)
		old.restart(t, "reuse", 100, time.Time{})

		next := newInstance(client, testGeneration)
		seen, err := next.Lookup(ctx, "reuse", testKey)
		require.NoError(t, err)
		require.NoError(t, next.ClaimReused(ctx, "reuse", seen, 200, testKey))

		_, ok := next.reusable(t, "reuse")
		assert.False(t, ok, "a claimed entry is not reusable while its new stream is open")
		applied, err := next.Advance(ctx, "reuse", 100, 9)
		require.NoError(t, err)
		assert.False(t, applied, "after a reuse only the new stream may advance the entry")
		applied, err = next.Advance(ctx, "reuse", 200, 8)
		require.NoError(t, err)
		assert.True(t, applied, "the new stream owns the entry")
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

func TestWaitStreams(t *testing.T) {
	c := New(nil, Config{})
	c.StreamStarted()

	done := make(chan struct{})
	go func() {
		c.WaitStreams(context.Background())
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("WaitStreams must wait for a running stream")
	case <-time.After(50 * time.Millisecond):
	}

	c.StreamEnded()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("WaitStreams must return once every stream ended")
	}

	c.StreamStarted()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	c.WaitStreams(ctx)
	assert.Error(t, ctx.Err(), "WaitStreams must give up when its context ends")
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
		t.Setenv(EnvResyncWindow, "2m")
		cfg := ConfigFromEnv("g")
		assert.True(t, cfg.Enabled, "enabled flag")
		assert.Equal(t, 3*time.Hour, cfg.MaxAge, "max age")
		assert.Equal(t, 2*time.Minute, cfg.ResyncWindow, "resync window")
	})

	t.Run("invalid values fall back", func(t *testing.T) {
		t.Setenv(EnvEnabled, "maybe")
		t.Setenv(EnvMaxAge, "0")
		t.Setenv(EnvResyncWindow, "0")
		cfg := ConfigFromEnv("g")
		assert.False(t, cfg.Enabled, "an unparseable flag must leave the cache off")
		assert.Equal(t, defaultMaxAge, cfg.MaxAge, "a zero max age must fall back to the default")
		assert.Equal(t, defaultResyncWindow, cfg.ResyncWindow, "the resync push cannot be turned off")
	})

	t.Run("a window above the cap falls back", func(t *testing.T) {
		t.Setenv(EnvResyncWindow, "24h")
		assert.Equal(t, defaultResyncWindow, ConfigFromEnv("g").ResyncWindow, "a huge window would disable the push in practice")
	})
}
