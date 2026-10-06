package certproof

import (
	"context"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/shared/management/certposture"
	"github.com/netbirdio/netbird/shared/management/proto"
)

const collectTimeout = 45 * time.Second

// collecting is the single-flight flag Collectors share by default. It outlives the
// engine, since a collection abandoned in a token, TPM or keychain call keeps running
// after the engine that started it has stopped, and the next engine must not start
// another one on top of it.
var collecting atomic.Bool

// Collector runs CollectProofs with a deadline and at most one collection at a time in
// the process. Token, TPM and keychain calls cannot be interrupted, so a collection that
// overruns is abandoned rather than awaited, and a new one is refused until it has
// finished. The zero value is ready to use.
type Collector struct {
	// busy overrides the process-wide single-flight flag when set.
	busy *atomic.Bool
	// timeout overrides collectTimeout when set.
	timeout time.Duration
}

// Collect answers the certificate challenges in checks, returning no proofs when there
// are no challenges, when a previous collection is still running, or when this one does
// not finish in time. Missing proofs fail the certificate check on management.
func (c *Collector) Collect(ctx context.Context, checks []*proto.Checks, peerKey []byte, cfg Config) []certposture.Proof {
	return c.collect(ctx, checks, func(ctx context.Context) []certposture.Proof {
		return CollectProofs(ctx, checks, peerKey, cfg)
	})
}

func (c *Collector) collect(ctx context.Context, checks []*proto.Checks, run func(context.Context) []certposture.Proof) []certposture.Proof {
	if len(certificateChallenges(checks)) == 0 {
		return nil
	}
	busy := c.flag()
	if !busy.CompareAndSwap(false, true) {
		log.Warnf("certificate posture: previous proof collection is still running, sending no proofs")
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, c.deadline())
	defer cancel()

	done := make(chan []certposture.Proof, 1)
	go func() {
		// The slot is freed before the result is delivered, so a caller that starts the
		// next collection right after this one returned is not turned away.
		proofs := run(ctx)
		busy.Store(false)
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

func (c *Collector) flag() *atomic.Bool {
	if c.busy != nil {
		return c.busy
	}
	return &collecting
}

func (c *Collector) deadline() time.Duration {
	if c.timeout > 0 {
		return c.timeout
	}
	return collectTimeout
}
