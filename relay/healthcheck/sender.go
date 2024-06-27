package healthcheck

import (
	"context"
	"time"
)

var (
	healthCheckInterval = 25 * time.Second
	healthCheckTimeout  = 5 * time.Second
)

// Sender is a healthcheck sender
// It will send healthcheck signal to the receiver
// If the receiver does not receive the signal in a certain time, it will send a timeout signal and stop to work
// It will also stop if the context is canceled
type Sender struct {
	HealthCheck chan struct{}
	Timeout     chan struct{}

	ctx context.Context
	ack chan struct{}
}

// NewSender creates a new healthcheck sender
func NewSender(ctx context.Context) *Sender {
	hc := &Sender{
		HealthCheck: make(chan struct{}, 1),
		Timeout:     make(chan struct{}, 1),
		ctx:         ctx,
		ack:         make(chan struct{}, 1),
	}

	go hc.healthCheck()
	return hc
}

func (hc *Sender) OnHCResponse() {
	select {
	case hc.ack <- struct{}{}:
	default:
	}
}

func (hc *Sender) healthCheck() {
	ticker := time.NewTicker(healthCheckInterval)
	defer ticker.Stop()

	timeoutTimer := time.NewTimer(healthCheckInterval + healthCheckTimeout)
	defer timeoutTimer.Stop()

	defer close(hc.HealthCheck)
	defer close(hc.Timeout)

	for {
		select {
		case <-ticker.C:
			hc.HealthCheck <- struct{}{}
		case <-timeoutTimer.C:
			hc.Timeout <- struct{}{}
			return
		case <-hc.ack:
			timeoutTimer.Stop()
		case <-hc.ctx.Done():
			return
		}
	}
}
