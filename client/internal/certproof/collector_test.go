package certproof

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/certposture"
	"github.com/netbirdio/netbird/shared/management/proto"
)

var challengeChecks = []*proto.Checks{{CertificateChallenge: &proto.CertificateChallenge{
	Nonce: certposture.NewChallenger([]byte("secret")).Nonce(peerKey, time.Now()),
}}}

func TestCollector_SkipsChecksWithoutChallenges(t *testing.T) {
	var c Collector
	called := false

	proofs := c.collect(context.Background(), []*proto.Checks{{Files: []string{"/bin/agent"}}}, func(context.Context) []certposture.Proof {
		called = true
		return nil
	})

	assert.Nil(t, proofs)
	assert.False(t, called, "no store is touched when no check carries a challenge")
}

func TestCollector_ReturnsProofs(t *testing.T) {
	var c Collector
	want := []certposture.Proof{{Nonce: []byte("nonce")}}

	proofs := c.collect(context.Background(), challengeChecks, func(context.Context) []certposture.Proof { return want })

	assert.Equal(t, want, proofs, "a collection that finishes in time is returned as is")
}

func TestCollector_AbandonsStuckCollection(t *testing.T) {
	c := Collector{timeout: 50 * time.Millisecond, slots: &collectSlots{}}
	release := make(chan struct{})
	finished := make(chan struct{})

	// A token or keychain call that ignores its context and blocks well past the deadline.
	stuck := func(context.Context) []certposture.Proof {
		defer close(finished)
		<-release
		return []certposture.Proof{{Nonce: []byte("late")}}
	}

	start := time.Now()
	proofs := c.collect(context.Background(), challengeChecks, stuck)
	assert.Nil(t, proofs, "an overrunning collection yields no proofs")
	assert.Less(t, time.Since(start), time.Second, "the caller is released at the deadline, not when the call returns")

	called := false
	proofs = c.collect(context.Background(), challengeChecks, func(context.Context) []certposture.Proof {
		called = true
		return nil
	})
	assert.Nil(t, proofs)
	assert.False(t, called, "no second collection starts while the first is still running")

	close(release)
	<-finished
	require.Eventually(t, func() bool { return c.slots.idle() }, time.Second, 5*time.Millisecond, "the collector frees up once the stuck call returns")

	want := []certposture.Proof{{Nonce: []byte("nonce")}}
	assert.Equal(t, want, c.collect(context.Background(), challengeChecks, func(context.Context) []certposture.Proof { return want }),
		"collection works again after the stuck call returned")
}

func TestCollector_CancelsContextAtDeadline(t *testing.T) {
	c := Collector{timeout: 20 * time.Millisecond, slots: &collectSlots{}}
	cancelled := make(chan struct{})

	c.collect(context.Background(), challengeChecks, func(ctx context.Context) []certposture.Proof {
		<-ctx.Done()
		close(cancelled)
		return nil
	})

	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("a collection that honours its context, like the helper process, must see it cancelled")
	}
}

// TestCollector_SingleFlightAcrossCollectors: each engine has its own Collector, and a
// collection stuck in a token call outlives the engine that started it, so the next
// engine's Collector must not start another one until it has finished.
func TestCollector_SingleFlightAcrossCollectors(t *testing.T) {
	shared := &collectSlots{}
	first := Collector{timeout: 20 * time.Millisecond, slots: shared}
	second := Collector{timeout: time.Second, slots: shared}

	release := make(chan struct{})
	stuck := func(context.Context) []certposture.Proof {
		<-release
		return nil
	}
	assert.Nil(t, first.collect(context.Background(), challengeChecks, stuck), "the first collection is abandoned at its deadline")

	called := false
	proofs := second.collect(context.Background(), challengeChecks, func(context.Context) []certposture.Proof {
		called = true
		return []certposture.Proof{{}}
	})
	assert.Nil(t, proofs, "no proofs while the abandoned collection still runs")
	assert.False(t, called, "a second collection does not start on top of the abandoned one")

	close(release)
	require.Eventually(t, func() bool { return shared.idle() }, time.Second, 5*time.Millisecond)
	assert.Len(t, second.collect(context.Background(), challengeChecks, func(context.Context) []certposture.Proof { return []certposture.Proof{{}} }), 1,
		"collections resume once the abandoned one finished")
}

// TestCollector_ZeroValuesShareTheProcessFlag: the zero value uses the process-wide flag.
func TestCollector_ZeroValuesShareTheProcessFlag(t *testing.T) {
	var a, b Collector
	assert.Same(t, a.slotsInUse(), b.slotsInUse(), "separate Collectors share the process slots")
}

// TestCollector_LostCollectionDoesNotBlockForever: a store call that never answers, such
// as a wedged token on Linux where there is no process to kill, must not refuse every
// later collection. Once it has run for lostAfter deadlines another starts beside it,
// and no more than maxInFlight ever run.
func TestCollector_LostCollectionDoesNotBlockForever(t *testing.T) {
	now := time.Now()
	slots := &collectSlots{}
	c := Collector{timeout: 10 * time.Millisecond, slots: slots, now: func() time.Time { return now }}

	release := make(chan struct{})
	defer close(release)
	var started atomic.Int32
	wedged := func(context.Context) []certposture.Proof {
		started.Add(1)
		<-release
		return nil
	}

	c.collect(context.Background(), challengeChecks, wedged)
	waitStarted(t, &started, 1)
	c.collect(context.Background(), challengeChecks, wedged)
	assert.Equal(t, int32(1), started.Load(), "a second collection is refused while the first may still finish")
	assert.False(t, c.Stuck(), "one slow collection is not stuck yet")

	now = now.Add(time.Duration(lostAfter) * c.deadline())
	c.collect(context.Background(), challengeChecks, wedged)
	waitStarted(t, &started, 2)
	assert.False(t, c.Stuck(), "the second collection may still return, so the collector is not stuck yet")

	now = now.Add(time.Duration(lostAfter) * c.deadline())
	c.collect(context.Background(), challengeChecks, wedged)
	assert.Equal(t, int32(2), started.Load(), "no more than maxInFlight collections run")
	assert.True(t, c.Stuck(), "with every slot held by a lost collection the collector reports itself stuck")
}

// TestCollector_LostWindowFollowsTheOldestRunningCollection: A wedges, B starts beside it
// once A counts as lost, then A returns. B is recent, so a third collection must wait for
// B to be lost in its own right rather than inherit A's start time.
func TestCollector_LostWindowFollowsTheOldestRunningCollection(t *testing.T) {
	now := time.Now()
	slots := &collectSlots{}
	c := Collector{timeout: 10 * time.Millisecond, slots: slots, now: func() time.Time { return now }}
	lost := time.Duration(lostAfter) * c.deadline()

	releaseA := make(chan struct{})
	releaseB := make(chan struct{})
	defer close(releaseB)
	var started atomic.Int32
	blockOn := func(release chan struct{}) func(context.Context) []certposture.Proof {
		return func(context.Context) []certposture.Proof {
			started.Add(1)
			<-release
			return nil
		}
	}

	c.collect(context.Background(), challengeChecks, blockOn(releaseA))
	waitStarted(t, &started, 1)
	now = now.Add(lost)
	c.collect(context.Background(), challengeChecks, blockOn(releaseB))
	waitStarted(t, &started, 2)

	close(releaseA)
	require.Eventually(t, func() bool {
		slots.mu.Lock()
		defer slots.mu.Unlock()
		return len(slots.running) == 1
	}, time.Second, 5*time.Millisecond, "A frees its slot once it returns")

	c.collect(context.Background(), challengeChecks, blockOn(make(chan struct{})))
	assert.Equal(t, int32(2), started.Load(), "a third collection waits while B is recent")
}

// waitStarted waits for the collections the test launched to have started. collect may
// return at its deadline before the goroutine running the store call was scheduled.
func waitStarted(t *testing.T, started *atomic.Int32, n int32) {
	t.Helper()
	require.Eventually(t, func() bool { return started.Load() == n }, time.Second, time.Millisecond,
		"%d collections should have started", n)
}
