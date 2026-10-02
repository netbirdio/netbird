package certproof

import (
	"context"
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
	c := Collector{timeout: 50 * time.Millisecond}
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
	require.Eventually(t, c.idle, time.Second, 5*time.Millisecond, "the collector frees up once the stuck call returns")

	want := []certposture.Proof{{Nonce: []byte("nonce")}}
	assert.Equal(t, want, c.collect(context.Background(), challengeChecks, func(context.Context) []certposture.Proof { return want }),
		"collection works again after the stuck call returned")
}

func TestCollector_CancelsContextAtDeadline(t *testing.T) {
	c := Collector{timeout: 20 * time.Millisecond}
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

func TestCollector_StartsAnotherOnceAWedgedOneIsLost(t *testing.T) {
	// On Linux a wedged token or TPM read blocks in this process: there is no helper to
	// kill and no wait delay to apply, so the collection never returns. Holding the slot
	// for it would mean the peer never proves its certificate again, failing the check
	// for good over a fault that may have passed.
	c := Collector{timeout: 20 * time.Millisecond}
	clock := time.Now()
	c.now = func() time.Time { return clock }

	stuck := make(chan struct{})
	t.Cleanup(func() { close(stuck) })
	require.Nil(t, c.collect(context.Background(), challengeChecks,
		func(context.Context) []certposture.Proof { <-stuck; return nil }))

	healthy := func(context.Context) []certposture.Proof { return []certposture.Proof{{Nonce: []byte("n")}} }

	assert.Nil(t, c.collect(context.Background(), challengeChecks, healthy),
		"while the wedged one may still be merely slow, nothing else starts")

	clock = clock.Add(lostAfter * c.deadline())
	assert.Len(t, c.collect(context.Background(), challengeChecks, healthy), 1,
		"once it is clearly lost, a healthy collection runs beside it")
}

func TestCollector_StopsPilingUpWedgedCollections(t *testing.T) {
	c := Collector{timeout: 20 * time.Millisecond}
	clock := time.Now()
	c.now = func() time.Time { return clock }

	stuck := make(chan struct{})
	t.Cleanup(func() { close(stuck) })
	wedged := func(context.Context) []certposture.Proof { <-stuck; return nil }

	for range maxInFlight {
		require.Nil(t, c.collect(context.Background(), challengeChecks, wedged))
		clock = clock.Add(lostAfter * c.deadline())
	}

	called := false
	assert.Nil(t, c.collect(context.Background(), challengeChecks, func(context.Context) []certposture.Proof {
		called = true
		return nil
	}))
	assert.False(t, called, "a store that never answers must not leak a goroutine per sync")
}
