package healthcheck

import (
	"context"
	"os"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	defaultAttemptThreshold    = 1
	defaultAttemptThresholdEnv = "NB_RELAY_HC_ATTEMPT_THRESHOLD"
)

var (
	heartbeatTimeout = healthCheckInterval + 10*time.Second
)

// Receiver is a healthcheck receiver
// It will listen for heartbeat and check if the heartbeat is not received in a certain time
// If the heartbeat is not received in a certain time, it will send a timeout signal and stop to work
// The heartbeat timeout is a bit longer than the sender's healthcheck interval
type Receiver struct {
	OnTimeout chan struct{}

	ctx              context.Context
	ctxCancel        context.CancelFunc
	heartbeat        chan struct{}
	alive            bool
	attemptThreshold int
}

// NewReceiver creates a new healthcheck receiver and start the timer in the background
func NewReceiver() *Receiver {
	ctx, ctxCancel := context.WithCancel(context.Background())

	r := &Receiver{
		OnTimeout:        make(chan struct{}, 1),
		ctx:              ctx,
		ctxCancel:        ctxCancel,
		heartbeat:        make(chan struct{}, 1),
		attemptThreshold: getAttemptThresholdFromEnv(),
	}

	go r.waitForHealthcheck()
	return r
}

func getAttemptThresholdFromEnv() int {
	if attemptThreshold := os.Getenv(defaultAttemptThresholdEnv); attemptThreshold != "" {
		threshold, err := strconv.ParseInt(attemptThreshold, 10, 64)
		if err != nil {
			log.Errorf("Failed to parse attempt threshold from environment variable \"%s\" should be an integer. Using default value", attemptThreshold)
			return defaultAttemptThreshold
		}
		return int(threshold)
	}
	return defaultAttemptThreshold
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
