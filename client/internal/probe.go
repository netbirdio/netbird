package internal

import "context"

// Probe allows to run on-demand callbacks from different code locations.
// Pass the probe to a receiving and a sending end. The receiving end starts listening
// to requests with Receive and executes a callback when the sending end requests it
// by calling Probe.
type Probe struct {
	request chan struct{}
	result  chan bool
	ready   bool
}

// NewProbe returns a new initialized probe.
func NewProbe() *Probe {
	return &Probe{
		request: make(chan struct{}),
		result:  make(chan bool),
	}
}

// Probe requests the callback to be run and returns a bool indicating success.
// It always returns true as long as the receiver is not ready.
func (p *Probe) Probe() bool {
	if !p.ready {
		return true
	}

	p.request <- struct{}{}
	return <-p.result
}

// Receive starts listening for probe requests. On such a request it runs the supplied
// callback func which must return a bool indicating success.
// Blocks until the passed context is cancelled.
func (p *Probe) Receive(ctx context.Context, callback func() bool) {
	p.ready = true
	defer func() {
		p.ready = false
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-p.request:
			p.result <- callback()
		}
	}
}
