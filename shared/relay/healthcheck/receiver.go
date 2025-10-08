package healthcheck

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	defaultHeartbeatTimeout = defaultHealthCheckInterval + 10*time.Second
)

type ReceiverOptions struct {
	HeartbeatTimeout time.Duration
	AttemptThreshold int
}

// Receiver is a healthcheck receiver
// It will listen for heartbeat and check if the heartbeat is not received in a certain time
// If the heartbeat is not received in a certain time, it will send a timeout signal and stop to work
// The heartbeat timeout is a bit longer than the sender's healthcheck interval
type Receiver struct {
	OnTimeout        chan struct{}
	log              *log.Entry
	ctx              context.Context
	ctxCancel        context.CancelFunc
	heartbeat        chan struct{}
	alive            bool
	attemptThreshold int
}

// NewReceiver creates a new healthcheck receiver and start the timer in the background
func NewReceiver(log *log.Entry) *Receiver {
	opts := ReceiverOptions{
		HeartbeatTimeout: defaultHeartbeatTimeout,
		AttemptThreshold: getAttemptThresholdFromEnv(),
	}
	return NewReceiverWithOpts(log, opts)
}

func NewReceiverWithOpts(log *log.Entry, opts ReceiverOptions) *Receiver {
	heartbeatTimeout := opts.HeartbeatTimeout
	if heartbeatTimeout <= 0 {
		heartbeatTimeout = defaultHeartbeatTimeout
	}
	attemptThreshold := opts.AttemptThreshold
	if attemptThreshold <= 0 {
		attemptThreshold = defaultAttemptThreshold
	}

	ctx, ctxCancel := context.WithCancel(context.Background())

	r := &Receiver{
		OnTimeout:        make(chan struct{}, 1),
		log:              log,
		ctx:              ctx,
		ctxCancel:        ctxCancel,
		heartbeat:        make(chan struct{}, 1),
		attemptThreshold: attemptThreshold,
	}

	go r.waitForHealthcheck(heartbeatTimeout)
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

func (r *Receiver) waitForHealthcheck(heartbeatTimeout time.Duration) {
	ticker := time.NewTicker(heartbeatTimeout)
	defer ticker.Stop()
	defer r.ctxCancel()
	defer close(r.OnTimeout)

	failureCounter := 0
	for {
		select {
		case <-r.heartbeat:
			r.alive = true
			failureCounter = 0
		case <-ticker.C:
			if r.alive {
				r.alive = false
				continue
			}

			failureCounter++
			if failureCounter < r.attemptThreshold {
				r.log.Warnf("healthcheck failed, attempt %d", failureCounter)
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
