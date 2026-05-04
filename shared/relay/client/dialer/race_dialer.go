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

func (r *RaceDial) Dial(ctx context.Context) (net.Conn, error) {
	connChan := make(chan dialResult, len(r.dialerFns))
	winnerConn := make(chan net.Conn, 1)
	abortCtx, abort := context.WithCancel(ctx)
	defer abort()

	for _, dfn := range r.dialerFns {
		go r.dial(dfn, abortCtx, connChan)
	}

	go r.processResults(connChan, winnerConn, abort)

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

func (r *RaceDial) processResults(connChan chan dialResult, winnerConn chan net.Conn, abort context.CancelFunc) {
	var hasWinner bool
	for i := 0; i < len(r.dialerFns); i++ {
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
