package keepalive

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
)

// Receiver tracks the deadline of a protocol version 2 client on the server side.
type Receiver struct {
	OnTimeout chan struct{}

	log       *log.Entry
	allowance time.Duration
	refresh   chan struct{}
	ctx       context.Context
	ctxCancel context.CancelFunc
}

// NewReceiver starts the deadline for a connection whose auth response has just been sent.
func NewReceiver(log *log.Entry) *Receiver {
	ctx, cancel := context.WithCancel(context.Background())
	r := &Receiver{
		OnTimeout: make(chan struct{}, 1),
		log:       log,
		allowance: durationFromEnv(envAllowance, defaultAllowance),
		refresh:   make(chan struct{}, 1),
		ctx:       ctx,
		ctxCancel: cancel,
	}
	go r.run()
	return r
}

// Allowance returns the time a client has between two keepalive requests.
func (r *Receiver) Allowance() time.Duration {
	return r.allowance
}

// Refresh moves the deadline after a valid keepalive request.
func (r *Receiver) Refresh() {
	select {
	case r.refresh <- struct{}{}:
	default:
	}
}

// Stop ends the deadline tracking without signaling a timeout.
func (r *Receiver) Stop() {
	r.ctxCancel()
}

func (r *Receiver) run() {
	defer r.ctxCancel()
	defer close(r.OnTimeout)

	timer := time.NewTimer(r.allowance)
	defer timer.Stop()

	for {
		select {
		case <-r.refresh:
			timer.Reset(r.allowance)
		case <-timer.C:
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
