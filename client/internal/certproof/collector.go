package certproof

import (
	"context"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/shared/management/certposture"
	"github.com/netbirdio/netbird/shared/management/proto"
)

const (
	collectTimeout = 10 * time.Second

	// lostAfter is how long an abandoned collection is waited for before a new one is
	// allowed to start alongside it. Deliberately many times the deadline: a store that
	// is merely slow should finish and release the slot on its own, and only one that
	// is wedged for good should be worked around.
	lostAfter = 10

	// maxInFlight bounds how many abandoned collections may pile up. A store that never
	// answers would otherwise leak a goroutine on every sync for the life of the daemon.
	maxInFlight = 2
)

// Collector runs CollectProofs with a deadline and, in the normal case, one collection
// at a time. Token, TPM and keychain calls cannot be interrupted — on Linux there is not
// even a process to kill — so a collection that overruns is abandoned rather than
// awaited. The zero value is ready to use.
//
// Abandoning is why the slot has to expire. A single wedged call would otherwise hold it
// for the life of the daemon and the peer would never send another proof, failing the
// certificate check for good over what may have been a momentary fault. So once an
// abandoned collection is clearly lost another may start beside it, up to a small cap:
// recovery from a transient wedge, and a bounded leak when the store is simply dead.
type Collector struct {
	mu       sync.Mutex
	inFlight int
	oldest   time.Time

	// timeout overrides collectTimeout when set.
	timeout time.Duration
	// now overrides the clock in tests.
	now func() time.Time
}

// Collect answers the certificate challenges in checks, returning no proofs when there
// are no challenges, when too many previous collections are still running, or when this
// one does not finish in time. Missing proofs fail the certificate check on management.
func (c *Collector) Collect(ctx context.Context, checks []*proto.Checks, peerKey []byte, cfg Config) []certposture.Proof {
	return c.collect(ctx, checks, func(ctx context.Context) []certposture.Proof {
		return CollectProofs(ctx, checks, peerKey, cfg)
	})
}

func (c *Collector) collect(ctx context.Context, checks []*proto.Checks, run func(context.Context) []certposture.Proof) []certposture.Proof {
	if len(certificateChallenges(checks)) == 0 {
		return nil
	}
	if !c.start() {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, c.deadline())
	defer cancel()

	done := make(chan []certposture.Proof, 1)
	go func() {
		defer c.finish()
		done <- run(ctx)
	}()

	select {
	case proofs := <-done:
		return proofs
	case <-ctx.Done():
		log.Warnf("certificate posture: proof collection did not finish within %s, sending no proofs", c.deadline())
		return nil
	}
}

// start claims a slot, reporting whether the caller may collect.
func (c *Collector) start() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.clock()
	switch {
	case c.inFlight == 0:
	case c.inFlight >= maxInFlight:
		log.Warnf("certificate posture: %d proof collections are wedged, sending no proofs", c.inFlight)
		return false
	case now.Sub(c.oldest) < time.Duration(lostAfter)*c.deadline():
		log.Warnf("certificate posture: previous proof collection is still running, sending no proofs")
		return false
	default:
		log.Warnf("certificate posture: a proof collection has been stuck since %s, starting another", c.oldest.Format(time.RFC3339))
	}

	if c.inFlight == 0 {
		c.oldest = now
	}
	c.inFlight++
	return true
}

func (c *Collector) finish() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.inFlight--
	if c.inFlight == 0 {
		c.oldest = time.Time{}
	}
}

// idle reports whether no collection is running, for tests that wait for one to finish.
func (c *Collector) idle() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.inFlight == 0
}

func (c *Collector) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *Collector) deadline() time.Duration {
	if c.timeout > 0 {
		return c.timeout
	}
	return collectTimeout
}
