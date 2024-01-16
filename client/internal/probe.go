package internal

import "context"

type Probe struct {
	request chan struct{}
	result  chan bool
}

func NewProbe() *Probe {
	return &Probe{
		request: make(chan struct{}),
		result:  make(chan bool),
	}
}

func (p *Probe) Probe() bool {
	p.request <- struct{}{}
	return <-p.result
}

func (p *Probe) Receive(ctx context.Context, callback func() bool) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.request:
			p.result <- callback()
		}
	}
}
