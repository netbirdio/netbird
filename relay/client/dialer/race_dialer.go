package dialer

import (
	"context"
	"errors"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
)

var (
	connectionTimeout = 30 * time.Second
)

type DialerFn interface {
	Dial(ctx context.Context, address string) (net.Conn, error)
	Protocol() string
}

type dialResult struct {
	Conn     net.Conn
	Protocol string
	Err      error
}

func RaceDial(log *log.Entry, serverURL string, dialerFns ...DialerFn) (net.Conn, error) {
	connChan := make(chan dialResult, len(dialerFns))
	winnerConn := make(chan net.Conn, 1)
	abortCtx, abort := context.WithCancel(context.Background())
	defer abort()

	for _, d := range dialerFns {
		go func() {
			ctx, cancel := context.WithTimeout(abortCtx, connectionTimeout)
			defer cancel()

			log.Infof("dialing Relay server via %s", d.Protocol())
			conn, err := d.Dial(ctx, serverURL)
			connChan <- dialResult{Conn: conn, Protocol: d.Protocol(), Err: err}
		}()
	}

	go func() {
		var hasWinner bool
		for i := 0; i < len(dialerFns); i++ {
			dr := <-connChan
			if dr.Err != nil {
				if errors.Is(dr.Err, context.Canceled) {
					log.Infof("connection attempt aborted via: %s", dr.Protocol)
				} else {
					log.Errorf("failed to dial via %s: %s", dr.Protocol, dr.Err)
				}
				continue
			}

			if hasWinner {
				if cerr := dr.Conn.Close(); cerr != nil {
					log.Warnf("failed to close connection via %s: %s", dr.Protocol, cerr)
				}
				continue
			}

			log.Infof("successfully dialed via: %s", dr.Protocol)

			abort()
			hasWinner = true
			winnerConn <- dr.Conn
		}
		close(winnerConn)
	}()

	conn, ok := <-winnerConn
	if !ok {
		return nil, errors.New("failed to dial to Relay server on any protocol")
	}
	return conn, nil
}
