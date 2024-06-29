package healthcheck

import (
	"context"
	"time"
)

var (
	heartbeatTimeout = healthCheckInterval + 3*time.Second
)

// Receiver is a healthcheck receiver
// It will listen for heartbeat and check if the heartbeat is not received in a certain time
// If the heartbeat is not received in a certain time, it will send a timeout signal and stop to work
// It will also stop if the context is canceled
// The heartbeat timeout is a bit longer than the sender's healthcheck interval
type Receiver struct {
	OnTimeout chan struct{}

	ctx       context.Context
	ctxCancel context.CancelFunc
	heartbeat chan struct{}
	alive     bool
}

// NewReceiver creates a new healthcheck receiver and start the timer in the background
func NewReceiver() *Receiver {
	ctx, ctxCancel := context.WithCancel(context.Background())

	r := &Receiver{
		OnTimeout: make(chan struct{}, 1),
		ctx:       ctx,
		ctxCancel: ctxCancel,
		heartbeat: make(chan struct{}, 1),
	}

	go r.waitForHealthcheck()
	return r
}

// Heartbeat acknowledge the heartbeat has been received
func (r *Receiver) Heartbeat() {
	select {
	case r.heartbeat <- struct{}{}:
	default:
	}
}

// Stop check the timeout and do not send new notifications
func (r *Receiver) Stop() {
	r.ctxCancel()
}

func (r *Receiver) waitForHealthcheck() {
	ticker := time.NewTicker(heartbeatTimeout)
	defer ticker.Stop()
	defer r.ctxCancel()
	defer close(r.OnTimeout)

	for {
		select {
		case <-r.heartbeat:
			r.alive = true
		case <-ticker.C:
			if r.alive {
				r.alive = false
				continue
			}

			r.notifyTimeout()
			return
		case <-r.ctx.Done():
			return
		}
	}
}

func (r *Receiver) notifyTimeout() {
	select {
	case r.OnTimeout <- struct{}{}:
	default:
	}
}
