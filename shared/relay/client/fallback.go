package client

import (
	"context"
	"errors"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	raceTotalTimeout  = 60 * time.Second
	raceFallbackDelay = 10 * time.Second
)

type raceAttempt struct {
	conn net.Conn
	err  error
}

type connRace struct {
	racer             *ConnRacer
	peerKey           string
	remoteRelayServer RelayServer
	preferForeign     bool

	raceCtx         context.Context
	otherCtx        context.Context
	cancelPreferred context.CancelFunc
	cancelOther     context.CancelFunc
	results         chan raceAttempt
	fallbackTimer   *time.Timer

	otherStarted bool
	settled      int
	lastErr      error
}

type ConnRacer struct {
	home         *Client
	foreignStore *ForeignRelaysStore
}

func NewConnRacer(home *Client, foreignStore *ForeignRelaysStore) *ConnRacer {
	return &ConnRacer{
		home:         home,
		foreignStore: foreignStore,
	}
}

func (r *ConnRacer) Run(ctx context.Context, peerKey string, remoteRelayServer RelayServer, preferForeign bool) (net.Conn, error) {
	raceCtx, cancel := context.WithTimeout(ctx, raceTotalTimeout)
	defer cancel()

	preferredCtx, cancelPreferred := context.WithCancel(raceCtx)
	otherCtx, cancelOther := context.WithCancel(raceCtx)

	race := &connRace{
		racer:             r,
		peerKey:           peerKey,
		remoteRelayServer: remoteRelayServer,
		preferForeign:     preferForeign,
		raceCtx:           raceCtx,
		otherCtx:          otherCtx,
		cancelPreferred:   cancelPreferred,
		cancelOther:       cancelOther,
		results:           make(chan raceAttempt, 2),
		fallbackTimer:     time.NewTimer(raceFallbackDelay),
	}
	defer race.fallbackTimer.Stop()

	go func() {
		race.results <- r.open(preferredCtx, peerKey, remoteRelayServer, preferForeign)
	}()

	for {
		select {
		case <-race.fallbackTimer.C:
			race.startOther()
		case res := <-race.results:
			if conn, err, done := race.handleResult(res); done {
				return conn, err
			}
		case <-raceCtx.Done():
			return race.onTimeout()
		}
	}
}

func (c *connRace) startOther() {
	if c.otherStarted {
		return
	}
	c.otherStarted = true
	c.fallbackTimer.Stop()
	go func() {
		c.results <- c.racer.open(c.otherCtx, c.peerKey, c.remoteRelayServer, !c.preferForeign)
	}()
}

func (c *connRace) handleResult(res raceAttempt) (net.Conn, error, bool) {
	if (res.err == nil && res.conn != nil) || errors.Is(res.err, ErrConnAlreadyExists) {
		c.stop()
		return res.conn, res.err, true
	}

	c.lastErr = res.err
	c.settled++
	if !c.otherStarted {
		c.startOther()
		return nil, nil, false
	}
	if c.settled == 2 {
		c.cancelPreferred()
		c.cancelOther()
		return nil, c.lastErr, true
	}
	return nil, nil, false
}

func (c *connRace) onTimeout() (net.Conn, error) {
	c.stop()
	if c.lastErr != nil {
		return nil, c.lastErr
	}
	return nil, c.raceCtx.Err()
}

func (c *connRace) stop() {
	c.cancelPreferred()
	c.cancelOther()
	go c.racer.drainLoser(c.results, c.settled, c.otherStarted)
}

func (r *ConnRacer) open(ctx context.Context, peerKey string, remoteRelayServer RelayServer, foreign bool) raceAttempt {
	if foreign {
		conn, err := r.foreignStore.OpenConn(ctx, peerKey, remoteRelayServer)
		return raceAttempt{conn: conn, err: err}
	}
	conn, err := r.home.OpenConn(ctx, peerKey)
	return raceAttempt{conn: conn, err: err}
}

func (r *ConnRacer) drainLoser(results chan raceAttempt, settled int, otherStarted bool) {
	started := 1
	if otherStarted {
		started = 2
	}
	for i := settled; i < started; i++ {
		res := <-results
		if res.conn != nil {
			if err := res.conn.Close(); err != nil {
				log.Debugf("failed to close losing relay connection: %v", err)
			}
		}
	}
}
