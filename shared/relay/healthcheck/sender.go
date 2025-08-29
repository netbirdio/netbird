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
	healthCheckInterval = 25 * time.Second
	healthCheckTimeout  = 20 * time.Second
)

// Sender is a healthcheck sender
// It will send healthcheck signal to the receiver
// If the receiver does not receive the signal in a certain time, it will send a timeout signal and stop to work
// It will also stop if the context is canceled
type Sender struct {
	log *log.Entry
	// HealthCheck is a channel to send health check signal to the peer
	HealthCheck chan struct{}
	// Timeout is a channel to the health check signal is not received in a certain time
	Timeout chan struct{}

	ack              chan struct{}
	alive            bool
	attemptThreshold int
}

// NewSender creates a new healthcheck sender
func NewSender(log *log.Entry) *Sender {
	hc := &Sender{
		log:              log,
		HealthCheck:      make(chan struct{}, 1),
		Timeout:          make(chan struct{}, 1),
		ack:              make(chan struct{}, 1),
		attemptThreshold: getAttemptThresholdFromEnv(),
	}

	return hc
}

// OnHCResponse sends an acknowledgment signal to the sender
func (hc *Sender) OnHCResponse() {
	select {
	case hc.ack <- struct{}{}:
	default:
	}
}

func (hc *Sender) StartHealthCheck(ctx context.Context) {
	ticker := time.NewTicker(healthCheckInterval)
	defer ticker.Stop()

	timeoutTicker := time.NewTicker(hc.getTimeoutTime())
	defer timeoutTicker.Stop()

	defer close(hc.HealthCheck)
	defer close(hc.Timeout)

	failureCounter := 0
	for {
		select {
		case <-ticker.C:
			hc.HealthCheck <- struct{}{}
		case <-timeoutTicker.C:
			if hc.alive {
				hc.alive = false
				continue
			}

			failureCounter++
			if failureCounter < hc.attemptThreshold {
				hc.log.Warnf("Health check failed attempt %d.", failureCounter)
				continue
			}
			hc.Timeout <- struct{}{}
			return
		case <-hc.ack:
			failureCounter = 0
			hc.alive = true
		case <-ctx.Done():
			return
		}
	}
}

func (hc *Sender) getTimeoutTime() time.Duration {
	return healthCheckInterval + healthCheckTimeout
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
