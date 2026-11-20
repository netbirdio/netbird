package alignedhb

import (
	"context"
	"time"
)

// NextDelay returns the time from now until the first unix millisecond
// strictly after now whose offset inside the period equals phase.
func NextDelay(period, phase time.Duration, now time.Time) time.Duration {
	p := period.Milliseconds()
	if p < 1 {
		p = 1
	}
	target := phase.Milliseconds()
	x := now.UnixMilli() + 1
	x += ((target-x)%p + p) % p
	return time.UnixMilli(x).Sub(now)
}

// Ticker returns a channel that fires on every period at phase, measured on
// the clock now, until ctx is done. Each fire is computed from the clock, so
// the schedule does not drift. A tick the reader has not taken is dropped.
func Ticker(ctx context.Context, period, phase time.Duration, now func() time.Time) <-chan time.Time {
	ch := make(chan time.Time, 1)
	go func() {
		start := now()
		target := start.Add(NextDelay(period, phase, start))
		t := time.NewTimer(target.Sub(start))
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case fired := <-t.C:
				select {
				case ch <- fired:
				default:
				}
				// A timer can fire a little before its target. Counting from the
				// target then keeps the same slot from firing twice.
				base := now()
				if base.Before(target) {
					base = target
				}
				target = base.Add(NextDelay(period, phase, base))
				t.Reset(target.Sub(now()))
			}
		}
	}()
	return ch
}
