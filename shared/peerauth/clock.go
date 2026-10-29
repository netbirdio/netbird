package peerauth

import (
	"sync/atomic"
	"time"
)

// Clock is the time a peer signs its proofs on: the last Management time seen, advanced by the
// time elapsed since on the monotonic clock, so neither a wrong local clock nor a later step of
// it gets the proofs refused. The zero Clock and a nil *Clock are the local clock.
type Clock struct {
	ref atomic.Pointer[clockRef]
}

type clockRef struct {
	management time.Time
	// local carries the monotonic reading the elapsed time is measured from.
	local time.Time
}

// Now returns the last Management time seen, advanced by the time elapsed since.
func (c *Clock) Now() time.Time {
	if c == nil {
		return time.Now()
	}
	ref := c.ref.Load()
	if ref == nil {
		return time.Now()
	}
	return ref.management.Add(time.Since(ref.local))
}

// SetManagementTime records Management's time as of now.
func (c *Clock) SetManagementTime(t time.Time) {
	c.ref.Store(&clockRef{management: t, local: time.Now()})
}
