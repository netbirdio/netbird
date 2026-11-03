package keepalive

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/shared/relay/messages"
)

const pollInterval = 10 * time.Second

// Sender drives the client side of the protocol version 2 keepalive on one relay connection.
type Sender struct {
	OnTimeout chan struct{}

	log       *log.Entry
	write     func([]byte) (int, error)
	interval  time.Duration
	timeout   time.Duration
	allowance time.Duration
	response  chan struct{}
	ctx       context.Context
	ctxCancel context.CancelFunc

	lastRequest  time.Time
	lastResponse time.Time
	sentAt       time.Time
	outstanding  bool
}

// NewSender starts the keepalive loop for a connection whose auth response has just arrived.
func NewSender(log *log.Entry, write func([]byte) (int, error)) *Sender {
	ctx, cancel := context.WithCancel(context.Background())
	now := wallClock()
	s := &Sender{
		OnTimeout:    make(chan struct{}, 1),
		log:          log,
		write:        write,
		interval:     durationFromEnv(envInterval, defaultInterval),
		timeout:      durationFromEnv(envResponseTimeout, defaultResponseTimeout),
		allowance:    durationFromEnv(envAllowance, defaultAllowance),
		response:     make(chan struct{}, 1),
		ctx:          ctx,
		ctxCancel:    cancel,
		lastRequest:  now,
		lastResponse: now,
	}
	go s.run()
	return s
}

// OnResponse reports a keepalive response read from the connection.
func (s *Sender) OnResponse() {
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

	timeout := time.NewTimer(s.timeout)
	timeout.Stop()
	defer timeout.Stop()

	s.log.Debugf("relay keepalive started: interval %s, response timeout %s, allowance %s", s.interval, s.timeout, s.allowance)
	for {
		select {
		case <-ticker.C:
			if !s.poll(timeout) {
				return
			}
		case <-timeout.C:
			s.log.Debugf("relay keepalive: no response within %s, closing connection", s.timeout)
			s.notifyTimeout()
			return
		case <-s.response:
			s.handleResponse(timeout)
		case <-s.ctx.Done():
			return
		}
	}
}

func (s *Sender) poll(timeout *time.Timer) bool {
	if s.outstanding {
		return true
	}

	now := wallClock()
	sinceResponse := now.Sub(s.lastResponse)
	if sinceResponse > s.allowance {
		s.log.Debugf("relay keepalive: %s passed since the last response, above the allowance of %s, closing connection", sinceResponse, s.allowance)
		s.notifyTimeout()
		return false
	}

	sinceRequest := now.Sub(s.lastRequest)
	if sinceRequest >= 0 && sinceRequest < s.interval {
		return true
	}
	if sinceRequest > s.interval+pollInterval {
		s.log.Debugf("relay keepalive: %s passed since the last request, sending immediately", sinceRequest)
	}
	s.send(now, timeout)
	return true
}

func (s *Sender) send(now time.Time, timeout *time.Timer) {
	s.lastRequest = now
	s.sentAt = time.Now()
	s.outstanding = true
	timeout.Reset(s.timeout)
	s.log.Debugf("relay keepalive request sent")

	go func() {
		if _, err := s.write(messages.MarshalKeepaliveRequest()); err != nil {
			s.log.Debugf("relay keepalive request write failed: %s", err)
		}
	}()
}

func (s *Sender) handleResponse(timeout *time.Timer) {
	if !s.outstanding {
		s.log.Debugf("relay keepalive response without a pending request, ignoring")
		return
	}
	s.outstanding = false
	timeout.Stop()
	s.lastResponse = wallClock()
	s.log.Debugf("relay keepalive response received after %s", time.Since(s.sentAt))
}

func (s *Sender) notifyTimeout() {
	select {
	case s.OnTimeout <- struct{}{}:
	default:
	}
}

func wallClock() time.Time {
	return time.Now().Round(0)
}
