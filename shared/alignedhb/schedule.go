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
// the wall clock of now, until ctx is done. Each fire is computed from the
// clock, so the schedule does not drift. The channel holds one unread tick:
// a late reader still gets it, and ticks that fire while it waits are dropped.
func Ticker(ctx context.Context, period, phase time.Duration, now func() time.Time) <-chan time.Time {
	ch := make(chan time.Time, 1)
	go func() {
		start := now().Round(0)
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
				target = nextFire(period, phase, target, now())
				t.Reset(target.Sub(now().Round(0)))
			}
		}
	}()
	return ch
}

// nextFire returns the slot after the one that fired at slot. Both times are
// read on the wall clock only, because the phase lives on the wall clock: a
// timer that fires early, or a wall clock stepped back after the fire, would
// otherwise select the fired slot again. A step back of a full period or more
// restarts the schedule from now, so the ticker never pauses that long.
func nextFire(period, phase time.Duration, slot, now time.Time) time.Time {
	slot, now = slot.Round(0), now.Round(0)
	base := now
	if now.Before(slot) && slot.Sub(now) < period {
		base = slot
	}
	return base.Add(NextDelay(period, phase, base))
}
