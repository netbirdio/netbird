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
	c := Collector{timeout: 50 * time.Millisecond, busy: new(atomic.Bool)}
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
	require.Eventually(t, func() bool { return !c.busy.Load() }, time.Second, 5*time.Millisecond, "the collector frees up once the stuck call returns")

	want := []certposture.Proof{{Nonce: []byte("nonce")}}
	assert.Equal(t, want, c.collect(context.Background(), challengeChecks, func(context.Context) []certposture.Proof { return want }),
		"collection works again after the stuck call returned")
}

func TestCollector_CancelsContextAtDeadline(t *testing.T) {
	c := Collector{timeout: 20 * time.Millisecond, busy: new(atomic.Bool)}
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
	shared := new(atomic.Bool)
	first := Collector{timeout: 20 * time.Millisecond, busy: shared}
	second := Collector{timeout: time.Second, busy: shared}

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
	require.Eventually(t, func() bool { return !shared.Load() }, time.Second, 5*time.Millisecond)
	assert.Len(t, second.collect(context.Background(), challengeChecks, func(context.Context) []certposture.Proof { return []certposture.Proof{{}} }), 1,
		"collections resume once the abandoned one finished")
}

// TestCollector_ZeroValuesShareTheProcessFlag: the zero value uses the process-wide flag.
func TestCollector_ZeroValuesShareTheProcessFlag(t *testing.T) {
	var a, b Collector
	assert.Same(t, a.flag(), b.flag(), "separate Collectors share one single-flight flag")
}
