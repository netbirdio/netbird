package healthcheck

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/shared/alignedhb"
)

const (
	defaultAttemptThreshold = 1

	defaultHealthCheckInterval = 25 * time.Second
	defaultHealthCheckTimeout  = 20 * time.Second

	// alignedAckTimeout is how long past an aligned period the sender waits
	// for a health check answer before it closes a silent peer.
	alignedAckTimeout = 20 * time.Second
)

type SenderOptions struct {
	HealthCheckInterval time.Duration
	HealthCheckTimeout  time.Duration
	AttemptThreshold    int
	// Aligned, when set with a positive period, replaces the interval with the aligned
	// schedule from the start and the timeout with the period plus 20 s.
	Aligned *AlignedSchedule
}

// AlignedSchedule is the aligned heartbeat schedule of one connection: a
// send on every Period at Phase, measured on the server wall clock.
type AlignedSchedule struct {
	Period time.Duration
	Phase  time.Duration
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
	aligned          *AlignedSchedule
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
	if opts.Aligned != nil && opts.Aligned.Period > 0 {
		aligned := *opts.Aligned
		hc.aligned = &aligned
		hc.timeout = alignedTimeout(aligned.Period)
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

// NewAlignedSender creates a healthcheck sender that sends on the aligned schedule s from
// the start, with the attempt threshold of NewSender.
func NewAlignedSender(log *log.Entry, s AlignedSchedule) *Sender {
	opts := SenderOptions{
		AttemptThreshold: getAttemptThresholdFromEnv(),
		Aligned:          &s,
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
	tick, stopTick := hc.tickChannel(ctx)
	defer stopTick()

	timeoutTicker := time.NewTicker(hc.timeout)
	defer timeoutTicker.Stop()

	defer close(hc.HealthCheck)
	defer close(hc.Timeout)

	failureCounter := 0
	for {
		select {
		case <-tick:
			hc.requestHealthCheck()
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

// tickChannel returns the send tick and its stop func: the aligned schedule
// when set, else the stock interval.
func (hc *Sender) tickChannel(ctx context.Context) (<-chan time.Time, func()) {
	if hc.aligned != nil {
		hc.log.Debugf("aligned heartbeat on, period %s, phase %d ms", hc.aligned.Period, hc.aligned.Phase.Milliseconds())
		tickCtx, cancel := context.WithCancel(ctx)
		return alignedhb.Ticker(tickCtx, hc.aligned.Period, hc.aligned.Phase, time.Now), cancel
	}
	ticker := time.NewTicker(hc.healthCheckInterval)
	return ticker.C, ticker.Stop
}

func (hc *Sender) requestHealthCheck() {
	select {
	case hc.HealthCheck <- struct{}{}:
	default:
	}
}

// alignedTimeout returns how long the sender waits for an answer on an
// aligned connection before it closes the peer: the period plus 20 s.
func alignedTimeout(period time.Duration) time.Duration {
	return period + alignedAckTimeout
}
