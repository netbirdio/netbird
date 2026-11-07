package healthcheck

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/shared/testhb"
)

const (
	defaultAttemptThreshold = 1

	defaultHealthCheckInterval = 25 * time.Second
	defaultHealthCheckTimeout  = 20 * time.Second

	// testHBMinAckMargin is the minimum time after a test heartbeat period
	// that the sender waits for an ack before it counts a failure.
	testHBMinAckMargin = 10 * time.Second
)

type SenderOptions struct {
	HealthCheckInterval time.Duration
	HealthCheckTimeout  time.Duration
	AttemptThreshold    int
	// PhaseKey is the testhb phase key of the peer. When set and testhb is
	// enabled, the send tick comes from testhb.Ticker instead of the interval.
	PhaseKey string
}

// Sender is a healthcheck sender
// It will send healthcheck signal to the receiver
// If the receiver does not receive the signal in a certain time, it will send a timeout signal and stop to work
// It will also stop if the context is canceled
type Sender struct {
	// HealthCheck is a channel to send health check signal to the peer
	HealthCheck chan struct{}
	// Timeout is a channel to the health check signal is not received in a certain time
	Timeout chan struct{}

	log                 *log.Entry
	healthCheckInterval time.Duration
	timeout             time.Duration

	ack              chan struct{}
	alive            bool
	attemptThreshold int
	phaseKey         string
}

func NewSenderWithOpts(log *log.Entry, opts SenderOptions) *Sender {
	if opts.HealthCheckInterval <= 0 {
		opts.HealthCheckInterval = defaultHealthCheckInterval
	}
	if opts.HealthCheckTimeout <= 0 {
		opts.HealthCheckTimeout = defaultHealthCheckTimeout
	}
	if opts.AttemptThreshold <= 0 {
		opts.AttemptThreshold = defaultAttemptThreshold
	}
	hc := &Sender{
		HealthCheck:         make(chan struct{}, 1),
		Timeout:             make(chan struct{}, 1),
		log:                 log,
		healthCheckInterval: opts.HealthCheckInterval,
		timeout:             opts.HealthCheckInterval + opts.HealthCheckTimeout,
		ack:                 make(chan struct{}, 1),
		attemptThreshold:    opts.AttemptThreshold,
	}

	if opts.PhaseKey != "" && testhb.Enabled() {
		hc.phaseKey = opts.PhaseKey
		hc.timeout = max(hc.timeout, testhb.PeriodFromEnv()+max(opts.HealthCheckTimeout, testHBMinAckMargin))
	}

	return hc
}

// NewSender creates a new healthcheck sender
func NewSender(log *log.Entry) *Sender {
	opts := SenderOptions{
		HealthCheckInterval: defaultHealthCheckInterval,
		HealthCheckTimeout:  defaultHealthCheckTimeout,
		AttemptThreshold:    getAttemptThresholdFromEnv(),
	}
	return NewSenderWithOpts(log, opts)
}

// NewSenderWithPhaseKey creates a sender like NewSender that follows the
// testhb schedule for phaseKey when testhb is enabled.
func NewSenderWithPhaseKey(log *log.Entry, phaseKey string) *Sender {
	opts := SenderOptions{
		HealthCheckInterval: defaultHealthCheckInterval,
		HealthCheckTimeout:  defaultHealthCheckTimeout,
		AttemptThreshold:    getAttemptThresholdFromEnv(),
		PhaseKey:            phaseKey,
	}
	return NewSenderWithOpts(log, opts)
}

// OnHCResponse sends an acknowledgment signal to the sender
func (hc *Sender) OnHCResponse() {
	select {
	case hc.ack <- struct{}{}:
	default:
	}
}

func (hc *Sender) StartHealthCheck(ctx context.Context) {
	var tick <-chan time.Time
	if hc.phaseKey != "" {
		tick = testhb.Ticker(ctx, hc.phaseKey, testhb.ServiceRelay)
	}
	if tick == nil {
		ticker := time.NewTicker(hc.healthCheckInterval)
		defer ticker.Stop()
		tick = ticker.C
	}

	timeoutTicker := time.NewTicker(hc.timeout)
	defer timeoutTicker.Stop()

	defer close(hc.HealthCheck)
	defer close(hc.Timeout)

	failureCounter := 0
	for {
		select {
		case <-tick:
			hc.HealthCheck <- struct{}{}
			if hc.phaseKey != "" {
				hc.log.Infof("testhb: sent relay heartbeat key=%s mode=%s t=%d", hc.phaseKey, testhb.CurrentMode(), time.Now().UnixMilli())
			}
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
