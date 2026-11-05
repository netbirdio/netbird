package keepalive

import (
	"context"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/shared/relay/messages"
)

const maxResends = 3

var (
	pollInterval  = 10 * time.Second
	retryInterval = 5 * time.Second
)

// Sender drives the client side of the protocol version 2 keepalive on one relay connection.
type Sender struct {
	OnTimeout chan struct{}

	log       *log.Entry
	write     func([]byte) (int, error)
	interval  time.Duration
	timeout   time.Duration
	allowance time.Duration
	responses atomic.Uint64
	handoffs  atomic.Uint64
	handoffAt atomic.Pointer[time.Time]
	response  chan struct{}
	writeDone chan error
	ctx       context.Context
	ctxCancel context.CancelFunc

	lastRequest    time.Time
	lastResponse   time.Time
	sentAt         time.Time
	probeResponses uint64
	probeHandoffs  uint64
	attempts       int
	resends        int
	probing        bool
	handedOver     bool
	writing        bool
}

// NewSender starts the keepalive loop for a connection whose auth response has just arrived.
func NewSender(log *log.Entry, write func([]byte) (int, error)) *Sender {
	s := newSender(log, write)
	go s.run()
	return s
}

func newSender(log *log.Entry, write func([]byte) (int, error)) *Sender {
	ctx, cancel := context.WithCancel(context.Background())
	now := wallClock()
	return &Sender{
		OnTimeout:    make(chan struct{}, 1),
		log:          log,
		write:        write,
		interval:     durationFromEnv(envInterval, defaultInterval),
		timeout:      durationFromEnv(envResponseTimeout, defaultResponseTimeout),
		allowance:    durationFromEnv(envAllowance, defaultAllowance),
		response:     make(chan struct{}, 1),
		writeDone:    make(chan error, 1),
		ctx:          ctx,
		ctxCancel:    cancel,
		lastRequest:  now,
		lastResponse: now,
	}
}

// OnResponse records a keepalive response at the moment it is read from the connection.
func (s *Sender) OnResponse() {
	s.responses.Add(1)
	select {
	case s.response <- struct{}{}:
	default:
	}
}

// Stop ends the loop without signaling a timeout.
func (s *Sender) Stop() {
	s.ctxCancel()
}

func (s *Sender) run() {
	defer s.ctxCancel()
	defer close(s.OnTimeout)

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	timeout := newStoppedTimer()
	defer timeout.Stop()

	retry := newStoppedTimer()
	defer retry.Stop()

	s.log.Infof("relay keepalive started: interval %s, response timeout %s, retry interval %s, allowance %s", s.interval, s.timeout, retryInterval, s.allowance)
	for {
		select {
		case <-ticker.C:
			if !s.poll(timeout, retry) {
				return
			}
		case <-retry.C:
			s.resend(timeout, retry)
		case err := <-s.writeDone:
			s.handleWriteDone(err, timeout, retry)
		case <-timeout.C:
			if s.handleTimeout(timeout, retry) {
				return
			}
		case <-s.response:
			s.checkResponse(timeout, retry)
		case <-s.ctx.Done():
			return
		}
	}
}

func (s *Sender) poll(timeout, retry *time.Timer) bool {
	s.checkResponse(timeout, retry)
	if s.probing {
		return true
	}

	now := wallClock()
	sinceResponse := now.Sub(s.lastResponse)
	if sinceResponse > s.allowance {
		s.log.Infof("relay keepalive: %s passed since the last response, above the allowance of %s, closing connection", sinceResponse, s.allowance)
		s.notifyTimeout()
		return false
	}

	sinceRequest := now.Sub(s.lastRequest)
	if sinceRequest >= 0 && sinceRequest < s.interval {
		return true
	}
	if sinceRequest > s.interval+pollInterval {
		s.log.Infof("relay keepalive: %s passed since the last request, sending immediately", sinceRequest)
	}
	s.startProbe(now, timeout)
	return true
}

func (s *Sender) startProbe(now time.Time, timeout *time.Timer) {
	s.lastRequest = now
	s.probeResponses = s.responses.Load()
	s.probeHandoffs = s.handoffs.Load()
	s.attempts = 0
	s.resends = 0
	s.probing = true
	s.handedOver = false
	timeout.Reset(s.timeout)
	s.startWrite()
}

func (s *Sender) startWrite() {
	if s.writing {
		s.log.Infof("relay keepalive: previous request not yet handed to the transport, skipping this attempt")
		return
	}
	s.writing = true
	go func() {
		_, err := s.write(messages.MarshalKeepaliveRequest())
		if err == nil {
			at := time.Now()
			s.handoffAt.Store(&at)
			s.handoffs.Add(1)
		}
		s.writeDone <- err
	}()
}

func (s *Sender) resend(timeout, retry *time.Timer) {
	if !s.probing || s.checkResponse(timeout, retry) {
		return
	}
	select {
	case err := <-s.writeDone:
		s.handleWriteDone(err, timeout, retry)
		return
	default:
	}
	if s.resends >= maxResends {
		return
	}
	s.resends++
	s.log.Infof("relay keepalive: no response within %s, resending the request, resend %d of %d", retryInterval, s.resends, maxResends)
	s.startWrite()
}

func (s *Sender) handleWriteDone(err error, timeout, retry *time.Timer) {
	s.writing = false
	if !s.probing {
		return
	}
	if err != nil {
		s.log.Warnf("relay keepalive request write failed: %s", err)
		s.armRetry(retry)
		return
	}
	s.attempts++
	s.sentAt = *s.handoffAt.Load()
	s.checkHandoff(timeout)
	s.log.Infof("relay keepalive request sent, attempt %d", s.attempts)
	s.armRetry(retry)
}

func (s *Sender) armRetry(retry *time.Timer) {
	if s.resends >= maxResends {
		return
	}
	retry.Reset(retryInterval)
}

func (s *Sender) handleTimeout(timeout, retry *time.Timer) bool {
	if s.checkResponse(timeout, retry) {
		return false
	}
	if s.checkHandoff(timeout) {
		s.log.Infof("relay keepalive: request handed to the transport %s ago, waiting for the response", time.Since(s.sentAt))
		return false
	}
	if s.handedOver {
		s.log.Infof("relay keepalive: no response within %s of the first delivered request, closing connection", s.timeout)
	} else {
		s.log.Infof("relay keepalive: request not handed to the transport within %s, closing connection", s.timeout)
	}
	s.notifyTimeout()
	return true
}

func (s *Sender) checkResponse(timeout, retry *time.Timer) bool {
	if !s.probing || s.responses.Load() <= s.probeResponses {
		return false
	}
	s.probing = false
	timeout.Stop()
	retry.Stop()
	s.lastResponse = wallClock()
	s.log.Infof("relay keepalive response received after %s, attempt %d", time.Since(s.sentAt), s.attempts)
	return true
}

func (s *Sender) checkHandoff(timeout *time.Timer) bool {
	if s.handedOver || s.handoffs.Load() <= s.probeHandoffs {
		return false
	}
	s.handedOver = true
	at := *s.handoffAt.Load()
	s.sentAt = at
	timeout.Reset(s.timeout - time.Since(at))
	return true
}

func (s *Sender) notifyTimeout() {
	select {
	case s.OnTimeout <- struct{}{}:
	default:
	}
}

func newStoppedTimer() *time.Timer {
	t := time.NewTimer(time.Hour)
	t.Stop()
	return t
}

func wallClock() time.Time {
	return time.Now().Round(0)
}
