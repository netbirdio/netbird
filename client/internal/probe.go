package internal

import "context"

type Probe struct {
	request chan struct{}
	result  chan bool
	ready   bool
}

func NewProbe() *Probe {
	return &Probe{
		request: make(chan struct{}),
		result:  make(chan bool),
	}
}

func (p *Probe) Probe() bool {
	if !p.ready {
		return true
	}

	p.request <- struct{}{}
	return <-p.result
}

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
