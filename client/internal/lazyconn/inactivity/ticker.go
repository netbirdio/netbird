package inactivity

import "time"

var newTicker = func(d time.Duration) Ticker {
	return &realTicker{t: time.NewTicker(d)}
}

type Ticker interface {
	C() <-chan time.Time
	Reset(d time.Duration)
	Stop()
}

type realTicker struct {
	t *time.Ticker
}

func (r *realTicker) C() <-chan time.Time {
	return r.t.C
}

func (r *realTicker) Reset(d time.Duration) {
	r.t.Reset(d)
}

func (r *realTicker) Stop() {
	r.t.Stop()
}
