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
	live      bool
}

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

func (r *Receiver) Heartbeat() {
	select {
	case r.heartbeat <- struct{}{}:
	default:
	}
}

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
			r.live = true
		case <-ticker.C:
			if r.live {
				r.live = false
				continue
			}
			select {
			case r.OnTimeout <- struct{}{}:
			default:
			}
			return
		case <-r.ctx.Done():
			return
		}
	}
}
