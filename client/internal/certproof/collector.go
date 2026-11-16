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
	collectTimeout = 45 * time.Second

	// lostAfter is how many deadlines an abandoned collection is waited for before a new
	// one may start beside it. A store that is merely slow finishes well within that and
	// releases its slot; only one wedged for good is worked around.
	lostAfter = 10

	// maxInFlight bounds how many abandoned collections may pile up. A store that never
	// answers would otherwise leak a goroutine on every collection for the life of the
	// daemon.
	maxInFlight = 2
)

// collectSlots tracks the collections running in the process. Collectors share one by
// default: a collection abandoned in a token, TPM or keychain call keeps running after
// the engine that started it has stopped, and the next engine must account for it.
type collectSlots struct {
	mu   sync.Mutex
	next uint64
	// running holds the start time of each collection still running, by slot id.
	running map[uint64]time.Time
}

var processSlots collectSlots

// Collector runs CollectProofs with a deadline and, in the normal case, one collection
// at a time in the process. Token, TPM and keychain calls cannot be interrupted, and on
// Linux there is not even a process to kill, so a collection that overruns is abandoned
// rather than awaited. A single wedged call would then refuse every later collection for
// the life of the daemon, so once an abandoned collection has been running for lostAfter
// deadlines another may start beside it, up to maxInFlight. The zero value is ready to
// use.
type Collector struct {
	// slots overrides the process-wide slots when set.
	slots *collectSlots
	// timeout overrides collectTimeout when set.
	timeout time.Duration
	// now overrides the clock when set.
	now func() time.Time
}

// Collect answers the certificate challenges in checks, returning no proofs when there
// are no challenges, when previous collections still hold the slots, or when this one
// does not finish in time. Missing proofs fail the certificate check on management.
func (c *Collector) Collect(ctx context.Context, checks []*proto.Checks, peerKey []byte, cfg Config) []certposture.Proof {
	return c.collect(ctx, checks, func(ctx context.Context) []certposture.Proof {
		return CollectProofs(ctx, checks, peerKey, cfg)
	})
}

func (c *Collector) collect(ctx context.Context, checks []*proto.Checks, run func(context.Context) []certposture.Proof) []certposture.Proof {
	if len(certificateChallenges(checks)) == 0 {
		return nil
	}
	slots := c.slotsInUse()
	slot, ok := slots.start(c.clock(), time.Duration(lostAfter)*c.deadline())
	if !ok {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, c.deadline())
	defer cancel()

	done := make(chan []certposture.Proof, 1)
	go func() {
		// The slot is freed before the result is delivered, so a caller that starts the
		// next collection right after this one returned is not turned away.
		proofs := run(ctx)
		slots.finish(slot)
		done <- proofs
	}()

	select {
	case proofs := <-done:
		return proofs
	case <-ctx.Done():
		log.Warnf("certificate posture: proof collection did not finish within %s, sending no proofs", c.deadline())
		return nil
	}
}

// Stuck reports whether lost collections hold every slot. No collection starts again
// until one of them returns, which for a store that never answers means a restart.
func (c *Collector) Stuck() bool {
	return c.slotsInUse().allLost(c.clock(), time.Duration(lostAfter)*c.deadline())
}

func (c *Collector) slotsInUse() *collectSlots {
	if c.slots != nil {
		return c.slots
	}
	return &processSlots
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

// start claims a slot at now, reporting its id and whether the caller may collect. A
// collection that has held a slot for lost is taken to be wedged.
func (s *collectSlots) start(now time.Time, lost time.Duration) (uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.running) > 0 {
		oldest := s.oldest()
		switch {
		case len(s.running) >= maxInFlight:
			log.Warnf("certificate posture: %d proof collections are wedged, sending no proofs", len(s.running))
			return 0, false
		case now.Sub(oldest) < lost:
			log.Warnf("certificate posture: previous proof collection is still running, sending no proofs")
			return 0, false
		default:
			log.Warnf("certificate posture: a proof collection has been stuck since %s, starting another", oldest.Format(time.RFC3339))
		}
	}
	if s.running == nil {
		s.running = make(map[uint64]time.Time, maxInFlight)
	}
	s.next++
	s.running[s.next] = now
	return s.next, true
}

// finish releases the slot with the given id.
func (s *collectSlots) finish(slot uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.running, slot)
}

// allLost reports whether every slot is held by a collection that has run for lost.
func (s *collectSlots) allLost(now time.Time, lost time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.running) < maxInFlight {
		return false
	}
	for _, started := range s.running {
		if now.Sub(started) < lost {
			return false
		}
	}
	return true
}

// idle reports whether no collection is running.
func (s *collectSlots) idle() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.running) == 0
}

// oldest returns the start time of the longest-running collection. The caller holds mu
// and has checked that one is running.
func (s *collectSlots) oldest() time.Time {
	var oldest time.Time
	for _, started := range s.running {
		if oldest.IsZero() || started.Before(oldest) {
			oldest = started
		}
	}
	return oldest
}
