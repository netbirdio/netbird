package inalt

import (
	"time"
)

// fakeTicker is a controllable ticker for use in tests
type fakeTicker struct {
	ch       chan time.Time
	now      time.Time
	interval time.Duration
}

func newFakeTicker(d time.Duration) *fakeTicker {
	return &fakeTicker{
		ch:       make(chan time.Time, 1),
		now:      time.Now(),
		interval: d,
	}
}

// C returns the channel to receive "ticks" — does not push values itself
func (f *fakeTicker) C() <-chan time.Time {
	return f.ch
}

// Tick simulates advancing time and sending a tick
func (f *fakeTicker) Tick() {
	f.now = f.now.Add(f.interval) // use your desired interval
	f.ch <- f.now
}

// Stop is a no-op for fakeTicker
func (f *fakeTicker) Stop() {}
