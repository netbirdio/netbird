package dialer

import (
	"context"
	"errors"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	DefaultConnectionTimeout = 30 * time.Second
)

type DialeFn interface {
	// Dial connects to address. serverName, when non-empty, overrides the TLS
	// ServerName used for SNI/cert validation. Empty means derive from address.
	Dial(ctx context.Context, address, serverName string) (net.Conn, error)
	Protocol() string
}

type dialResult struct {
	Conn     net.Conn
	Protocol string
	Err      error
}

type RaceDial struct {
	log               *log.Entry
	serverURL         string
	serverName        string
	dialerFns         []DialeFn
	connectionTimeout time.Duration
	transportHint     []string
}

func NewRaceDial(log *log.Entry, connectionTimeout time.Duration, serverURL string, dialerFns ...DialeFn) *RaceDial {
	return &RaceDial{
		log:               log,
		serverURL:         serverURL,
		dialerFns:         dialerFns,
		connectionTimeout: connectionTimeout,
	}
}

// WithServerName sets a TLS SNI/cert validation override. Used when serverURL
// contains an IP literal but the cert is issued for a different hostname.
//
// Mutates the receiver and is not safe for concurrent reconfiguration; a
// RaceDial is intended to be constructed per dial and discarded.
func (r *RaceDial) WithServerName(serverName string) *RaceDial {
	r.serverName = serverName
	return r
}

// WithTransportHint restricts the dial race to dialers whose Protocol() is
// listed in hint. An empty or nil hint means "try every configured dialer"
// (legacy behavior). Used to skip dialers a relay has advertised it doesn't
// support — e.g. don't burn a WebTransport handshake on an old relay.
func (r *RaceDial) WithTransportHint(hint []string) *RaceDial {
	r.transportHint = hint
	return r
}

// activeDialers returns the subset of dialerFns that match the transport hint.
// With no hint set, all dialers are returned.
func (r *RaceDial) activeDialers() []DialeFn {
	if len(r.transportHint) == 0 {
		return r.dialerFns
	}
	allowed := make(map[string]struct{}, len(r.transportHint))
	for _, p := range r.transportHint {
		allowed[p] = struct{}{}
	}
	out := make([]DialeFn, 0, len(r.dialerFns))
	for _, d := range r.dialerFns {
		if _, ok := allowed[d.Protocol()]; ok {
			out = append(out, d)
		}
	}
	if len(out) == 0 {
		// Hint matched nothing the local build supports — fall back to all
		// rather than fail with no dialers. Mirrors race-dialer's "try
		// everything" default.
		r.log.Debugf("transport hint %v matched no local dialer; falling back to all", r.transportHint)
		return r.dialerFns
	}
	return out
}

func (r *RaceDial) Dial(ctx context.Context) (net.Conn, error) {
	dialers := r.activeDialers()
	connChan := make(chan dialResult, len(dialers))
	winnerConn := make(chan net.Conn, 1)
	abortCtx, abort := context.WithCancel(ctx)
	defer abort()

	for _, dfn := range dialers {
		go r.dial(dfn, abortCtx, connChan)
	}

	go r.processResults(connChan, winnerConn, abort, len(dialers))

	conn, ok := <-winnerConn
	if !ok {
		return nil, errors.New("failed to dial to Relay server on any protocol")
	}
	return conn, nil
}

func (r *RaceDial) dial(dfn DialeFn, abortCtx context.Context, connChan chan dialResult) {
	ctx, cancel := context.WithTimeout(abortCtx, r.connectionTimeout)
	defer cancel()

	r.log.Infof("dialing Relay server via %s", dfn.Protocol())
	conn, err := dfn.Dial(ctx, r.serverURL, r.serverName)
	connChan <- dialResult{Conn: conn, Protocol: dfn.Protocol(), Err: err}
}

func (r *RaceDial) processResults(connChan chan dialResult, winnerConn chan net.Conn, abort context.CancelFunc, total int) {
	var hasWinner bool
	for i := 0; i < total; i++ {
		dr := <-connChan
		if dr.Err != nil {
			if errors.Is(dr.Err, context.Canceled) {
				r.log.Infof("connection attempt aborted via: %s", dr.Protocol)
			} else {
				r.log.Errorf("failed to dial via %s: %s", dr.Protocol, dr.Err)
			}
			continue
		}

		if hasWinner {
			if cerr := dr.Conn.Close(); cerr != nil {
				r.log.Warnf("failed to close connection via %s: %s", dr.Protocol, cerr)
			}
			continue
		}

		r.log.Infof("successfully dialed via: %s", dr.Protocol)

		abort()
		hasWinner = true
		winnerConn <- dr.Conn
	}
	close(winnerConn)
}
