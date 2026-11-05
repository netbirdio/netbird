package keepalive

import (
	"context"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

// Receiver tracks the deadline of a protocol version 2 client on the server side.
type Receiver struct {
	OnTimeout chan struct{}

	log       *log.Entry
	allowance time.Duration
	requests  atomic.Uint64
	refresh   chan struct{}
	ctx       context.Context
	ctxCancel context.CancelFunc

	seenRequests uint64
}

// NewReceiver starts the deadline for a connection whose auth response has just been sent.
func NewReceiver(log *log.Entry) *Receiver {
	r := newReceiver(log)
	go r.run()
	return r
}

func newReceiver(log *log.Entry) *Receiver {
	ctx, cancel := context.WithCancel(context.Background())
	return &Receiver{
		OnTimeout: make(chan struct{}, 1),
		log:       log,
		allowance: durationFromEnv(envAllowance, defaultAllowance),
		refresh:   make(chan struct{}, 1),
		ctx:       ctx,
		ctxCancel: cancel,
	}
}

// Allowance returns the time a client has between two keepalive requests.
func (r *Receiver) Allowance() time.Duration {
	return r.allowance
}

// Refresh records a valid keepalive request at the moment it is read from the connection.
func (r *Receiver) Refresh() {
	r.requests.Add(1)
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
			r.checkRequests(timer)
		case <-timer.C:
			if r.handleExpiry(timer) {
				return
			}
		case <-r.ctx.Done():
			return
		}
	}
}

func (r *Receiver) handleExpiry(timer *time.Timer) bool {
	if r.checkRequests(timer) {
		return false
	}
	select {
	case r.OnTimeout <- struct{}{}:
	default:
	}
	return true
}

func (r *Receiver) checkRequests(timer *time.Timer) bool {
	n := r.requests.Load()
	if n <= r.seenRequests {
		return false
	}
	r.seenRequests = n
	timer.Reset(r.allowance)
	return true
}
