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
	// ClientSchedule is the testhb schedule the client sent, used in dynamic mode.
	ClientSchedule testhb.ClientSchedule
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
	clientSchedule   testhb.ClientSchedule
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
		hc.clientSchedule = opts.ClientSchedule
		period := max(testhb.PeriodFromEnv(), opts.ClientSchedule.Period)
		hc.timeout = max(hc.timeout, period+max(opts.HealthCheckTimeout, testHBMinAckMargin))
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
	return NewSenderWithClientSchedule(log, phaseKey, testhb.ClientSchedule{})
}

// NewSenderWithClientSchedule creates a sender like NewSenderWithPhaseKey that
// also follows the schedule the client sent, in testhb dynamic mode.
func NewSenderWithClientSchedule(log *log.Entry, phaseKey string, cs testhb.ClientSchedule) *Sender {
	opts := SenderOptions{
		HealthCheckInterval: defaultHealthCheckInterval,
		HealthCheckTimeout:  defaultHealthCheckTimeout,
		AttemptThreshold:    getAttemptThresholdFromEnv(),
		PhaseKey:            phaseKey,
		ClientSchedule:      cs,
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
		tick = testhb.TickerWithClient(ctx, hc.phaseKey, testhb.ServiceRelay, hc.clientSchedule)
		if tick != nil && hc.clientSchedule.OK {
			hc.log.Infof("testhb: client schedule svc=relay key=%s p=%d period=%d skew=%d", hc.phaseKey,
				hc.clientSchedule.PhaseMs, int64(hc.clientSchedule.Period/time.Second), hc.clientSchedule.SkewMs)
		}
	}
	// stockTick stays nil, and never fires, unless the client sent no schedule.
	var stockTick <-chan time.Time
	if tick == nil {
		ticker := time.NewTicker(hc.healthCheckInterval)
		defer ticker.Stop()
		tick = ticker.C
	} else if !hc.clientSchedule.OK {
		// Dynamic mode never fires for a client that sent no schedule, so a
		// stock client keeps the stock interval while that mode is active.
		ticker := time.NewTicker(hc.healthCheckInterval)
		defer ticker.Stop()
		stockTick = ticker.C
	}

	timeoutTicker := time.NewTicker(hc.timeout)
	defer timeoutTicker.Stop()

	defer close(hc.HealthCheck)
	defer close(hc.Timeout)

	failureCounter := 0
	for {
		select {
		case <-tick:
			if hc.testHBMuted() {
				hc.log.Infof("testhb: muted relay heartbeat key=%s", hc.phaseKey)
				continue
			}
			sent := hc.requestHealthCheck()
			hc.logTestHBSend(sent)
		case <-stockTick:
			if testhb.CurrentMode() != testhb.ModeDynamic || hc.testHBMuted() {
				continue
			}
			hc.requestHealthCheck()
		case <-timeoutTicker.C:
			// No acks come back while the sends are muted, so do not count them.
			if hc.testHBMuted() {
				failureCounter = 0
				hc.alive = true
				continue
			}
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

// requestHealthCheck queues a healthcheck without blocking. It reports false
// when the previous request is still unread, so this one is dropped.
func (hc *Sender) requestHealthCheck() bool {
	select {
	case hc.HealthCheck <- struct{}{}:
		return true
	default:
		return false
	}
}

func (hc *Sender) logTestHBSend(sent bool) {
	if hc.phaseKey == "" {
		return
	}
	mode := testhb.CurrentMode()
	if !sent {
		hc.log.Warnf("testhb: dropped relay heartbeat key=%s mode=%s t=%d, previous one unread",
			hc.phaseKey, mode, time.Now().UnixMilli())
		return
	}
	hc.log.Infof("testhb: sent relay heartbeat key=%s mode=%s t=%d%s",
		hc.phaseKey, mode, time.Now().UnixMilli(), testhb.LogSuffix(mode, hc.clientSchedule))
}

func (hc *Sender) testHBMuted() bool {
	return hc.phaseKey != "" && testhb.Muted(testhb.ServiceRelay)
}
