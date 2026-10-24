package mcpapi

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// startTestRedis returns the Redis of testRedisEnv, or one in a container.
func startTestRedis(t *testing.T) string {
	t.Helper()
	if redisURL := os.Getenv(testRedisEnv); redisURL != "" {
		return redisURL
	}
	testcontainers.SkipIfProviderIsNotHealthy(t)
	ctx := context.Background()
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "redis:7-alpine",
			ExposedPorts: []string{"6379/tcp"},
			WaitingFor:   wait.ForLog("Ready to accept connections"),
		},
		Started: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = container.Terminate(ctx) })
	host, err := container.Host(ctx)
	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "6379")
	require.NoError(t, err)
	return fmt.Sprintf("redis://%s:%s", host, port.Port())
}

// eachGrantStore runs a test against both stores, which must behave the same.
func eachGrantStore(t *testing.T, test func(t *testing.T, grants GrantStore)) {
	t.Run("memory", func(t *testing.T) {
		test(t, newMemoryGrants())
	})
	t.Run("redis", func(t *testing.T) {
		grants, err := newRedisGrants(context.Background(), startTestRedis(t))
		require.NoError(t, err)
		t.Cleanup(func() { _ = grants.client.Close() })
		test(t, grants)
	})
}

// newStoredGrant starts a grant under fresh IDs and returns its ID.
func newStoredGrant(t *testing.T, grants GrantStore, current string) string {
	t.Helper()
	codeID, err := randomToken()
	require.NoError(t, err)
	grantID, err := randomToken()
	require.NoError(t, err)
	record := grantRecord{UserID: "user-1", AccountID: "account-1", ClientKey: "client-1", Current: current}
	_, reused, err := grants.start(context.Background(), codeID, time.Minute, grantID, record, time.Hour)
	require.NoError(t, err)
	require.False(t, reused)
	return grantID
}

func TestGrantStoresStartOnce(t *testing.T) {
	eachGrantStore(t, func(t *testing.T, grants GrantStore) {
		ctx := context.Background()
		codeID, err := randomToken()
		require.NoError(t, err)
		record := grantRecord{UserID: "user-1", AccountID: "account-1", ClientKey: "client-1", Current: "r0", Started: 1_800_000_000}

		previous, reused, err := grants.start(ctx, codeID, time.Minute, "grant-a-"+codeID, record, time.Hour)
		require.NoError(t, err)
		assert.False(t, reused, "the first redemption starts a grant")
		assert.Empty(t, previous)

		previous, reused, err = grants.start(ctx, codeID, time.Minute, "grant-b-"+codeID, record, time.Hour)
		require.NoError(t, err)
		assert.True(t, reused, "the second redemption of a code starts nothing")
		assert.Equal(t, "grant-a-"+codeID, previous, "and names the grant the first one started")

		loaded, ok, err := grants.load(ctx, "grant-a-"+codeID)
		require.NoError(t, err)
		require.True(t, ok)
		assert.Equal(t, record, loaded, "the record round-trips")
		_, ok, err = grants.load(ctx, "grant-b-"+codeID)
		require.NoError(t, err)
		assert.False(t, ok, "the second redemption left no grant")
	})
}

func TestGrantStoresClaim(t *testing.T) {
	eachGrantStore(t, func(t *testing.T, grants GrantStore) {
		ctx := context.Background()
		key := usedLoginKeyPrefix + newStoredGrant(t, grants, "r0")
		first, err := grants.claim(ctx, key, time.Minute)
		require.NoError(t, err)
		assert.True(t, first)
		first, err = grants.claim(ctx, key, time.Minute)
		require.NoError(t, err)
		assert.False(t, first, "a key is claimed once")
	})
}

func TestGrantStoresRotate(t *testing.T) {
	eachGrantStore(t, func(t *testing.T, grants GrantStore) {
		ctx := context.Background()
		start := time.Unix(1_800_000_000, 0)
		rotate := func(grantID, presented, next string, at time.Time) (rotationOutcome, string) {
			t.Helper()
			outcome, current, err := grants.rotate(ctx, grantID, presented, next, at)
			require.NoError(t, err)
			return outcome, current
		}

		id := newStoredGrant(t, grants, "r0")
		outcome, current := rotate(id, "r0", "r1", start)
		assert.Equal(t, grantRotated, outcome, "the current token rotates")
		assert.Equal(t, "r1", current)

		outcome, current = rotate(id, "r1", "r2", start.Add(refreshGrace))
		assert.Equal(t, grantServed, outcome, "the new token does not rotate within the grace window")
		assert.Equal(t, "r1", current)
		outcome, current = rotate(id, "r0", "r2", start.Add(refreshGrace))
		assert.Equal(t, grantServed, outcome, "the replaced token is served within the grace window")
		assert.Equal(t, "r1", current)

		later := start.Add(refreshGrace + time.Millisecond)
		outcome, current = rotate(id, "r1", "r2", later)
		assert.Equal(t, grantRotated, outcome, "the current token rotates after the grace window")
		assert.Equal(t, "r2", current)
		record, ok, err := grants.load(ctx, id)
		require.NoError(t, err)
		require.True(t, ok)
		assert.Equal(t, grantRecord{UserID: "user-1", AccountID: "account-1", ClientKey: "client-1", Current: "r2", Previous: "r1", RotatedAt: later.UnixMilli()}, record)

		outcome, _ = rotate(id, "r0", "r3", later)
		assert.Equal(t, grantReplayed, outcome, "a token two rotations old is a replay")
		_, ok, err = grants.load(ctx, id)
		require.NoError(t, err)
		assert.False(t, ok, "a replay deletes the grant")
		outcome, _ = rotate(id, "r2", "r3", later)
		assert.Equal(t, grantGone, outcome, "the current token ends with the grant")

		id = newStoredGrant(t, grants, "r0")
		outcome, _ = rotate(id, "unknown", "r1", start)
		assert.Equal(t, grantReplayed, outcome, "a token the grant never issued is a replay")

		id = newStoredGrant(t, grants, "r0")
		require.NoError(t, grants.revoke(ctx, id))
		outcome, _ = rotate(id, "r0", "r1", start)
		assert.Equal(t, grantGone, outcome, "a revoked grant does not rotate")
		_, ok, err = grants.load(ctx, id)
		require.NoError(t, err)
		assert.False(t, ok, "a rotation does not bring a revoked grant back")
	})
}

// An instance whose clock is behind the one that rotated sees the rotation in the future.
// Skew within the grace window must not fail a burst, and a rotation further in the future
// is outside the window rather than inside it.
func TestGrantStoresBoundTheGraceWindowBothWays(t *testing.T) {
	eachGrantStore(t, func(t *testing.T, grants GrantStore) {
		ctx := context.Background()
		start := time.Unix(1_800_000_000, 0)
		id := newStoredGrant(t, grants, "r0")
		outcome, _, err := grants.rotate(ctx, id, "r0", "r1", start)
		require.NoError(t, err)
		require.Equal(t, grantRotated, outcome)

		outcome, current, err := grants.rotate(ctx, id, "r0", "r2", start.Add(-refreshGrace))
		require.NoError(t, err)
		assert.Equal(t, grantServed, outcome, "a clock up to the grace window behind is within it")
		assert.Equal(t, "r1", current)

		outcome, _, err = grants.rotate(ctx, id, "r0", "r2", start.Add(-refreshGrace-time.Millisecond))
		require.NoError(t, err)
		assert.Equal(t, grantReplayed, outcome, "a clock further behind is outside the grace window")
		_, ok, err := grants.load(ctx, id)
		require.NoError(t, err)
		assert.False(t, ok, "the replay deletes the grant")
	})
}

func TestGrantStoresExpire(t *testing.T) {
	eachGrantStore(t, func(t *testing.T, grants GrantStore) {
		ctx := context.Background()
		codeID, err := randomToken()
		require.NoError(t, err)
		grantID := "expiring-" + codeID
		_, _, err = grants.start(ctx, codeID, 50*time.Millisecond, grantID, grantRecord{UserID: "user-1", Current: "r0"}, 50*time.Millisecond)
		require.NoError(t, err)
		time.Sleep(100 * time.Millisecond)

		_, ok, err := grants.load(ctx, grantID)
		require.NoError(t, err)
		assert.False(t, ok, "a grant ends with its session")
		outcome, _, err := grants.rotate(ctx, grantID, "r0", "r1", time.Now())
		require.NoError(t, err)
		assert.Equal(t, grantGone, outcome)
		_, reused, err := grants.start(ctx, codeID, time.Minute, "again-"+codeID, grantRecord{Current: "r0"}, time.Minute)
		require.NoError(t, err)
		assert.False(t, reused, "a code's use marker lasts only as long as the code")
	})
}

func TestGrantStoresAreAtomic(t *testing.T) {
	eachGrantStore(t, func(t *testing.T, grants GrantStore) {
		ctx := context.Background()
		now := time.Unix(1_800_000_000, 0)

		t.Run("racing rotations rotate once", func(t *testing.T) {
			id := newStoredGrant(t, grants, "r0")
			const racers = 16
			var wg sync.WaitGroup
			outcomes := make([]rotationOutcome, racers)
			currents := make([]string, racers)
			for i := range racers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					var err error
					outcomes[i], currents[i], err = grants.rotate(ctx, id, "r0", fmt.Sprintf("next-%d", i), now)
					assert.NoError(t, err)
				}()
			}
			wg.Wait()
			rotated := 0
			for i := range racers {
				if outcomes[i] == grantRotated {
					rotated++
				}
				assert.Equal(t, currents[0], currents[i], "every racer gets the one new token")
			}
			assert.Equal(t, 1, rotated, "exactly one racer rotates, the rest are served: %v", outcomes)
		})

		t.Run("a revocation racing rotations stays revoked", func(t *testing.T) {
			for range 20 {
				id := newStoredGrant(t, grants, "r0")
				var wg sync.WaitGroup
				for i := range 8 {
					wg.Add(1)
					go func() {
						defer wg.Done()
						_, _, err := grants.rotate(ctx, id, "r0", fmt.Sprintf("next-%d", i), now)
						assert.NoError(t, err)
					}()
				}
				wg.Add(1)
				go func() {
					defer wg.Done()
					assert.NoError(t, grants.revoke(ctx, id))
				}()
				wg.Wait()
				_, ok, err := grants.load(ctx, id)
				require.NoError(t, err)
				require.False(t, ok, "no rotation writes a revoked grant back")
			}
		})
	})
}
