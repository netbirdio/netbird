package dialer

import (
	"context"
	"errors"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
)

type DialFn func(ctx context.Context, address string) (net.Conn, error)

type dialResult struct {
	Conn net.Conn
	Err  error
}

func RaceDial(serverURL string, DialFns ...DialFn) (net.Conn, error) {
	connChan := make(chan dialResult, len(DialFns))
	winnerConn := make(chan net.Conn, 1)
	abortCtx, abort := context.WithCancel(context.Background())
	defer abort()

	for _, dfn := range DialFns {
		go func() {
			ctx, cancel := context.WithTimeout(abortCtx, 30*time.Second)
			defer cancel()

			conn, err := dfn(ctx, serverURL)
			if err != nil {
				log.Errorf("failed to dial: %s", err)
			}

			connChan <- dialResult{Conn: conn, Err: err}
		}()
	}

	go func() {
		var hasWinner bool
		for i := 0; i < len(DialFns); i++ {
			dr := <-connChan
			if dr.Err != nil {
				continue
			}

			if hasWinner {
				_ = dr.Conn.Close()
				continue
			}

			hasWinner = true
			winnerConn <- dr.Conn
		}
		close(winnerConn)
	}()

	conn, ok := <-winnerConn
	if !ok {
		return nil, errors.New("failed to dial to Relay server")
	}
	return conn, nil
}
