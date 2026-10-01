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

var challengeChecks = []*proto.Checks{{CertificateChallenge: &proto.CertificateChallenge{Nonce: []byte("nonce")}}}

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
	require.Eventually(t, func() bool { return !c.busy.Load() }, time.Second, 5*time.Millisecond, "the collector frees up once the stuck call returns")

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
