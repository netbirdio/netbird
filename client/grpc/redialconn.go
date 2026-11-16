package grpc

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"

	"github.com/netbirdio/netbird/client/hbwatch"
)

// ConnDial creates a connection with the keepalive the stock marks give, and
// returns that keepalive time.
type ConnDial func(ctx context.Context) (*grpc.ClientConn, time.Duration, error)

// Redialer names a server and how to dial it again. Name is the service name
// in logs, Component and Addr key its stock mark.
type Redialer[C any] struct {
	Name      string
	Component string
	Addr      string
	Dial      ConnDial
	NewClient func(grpc.ClientConnInterface) C
}

// RedialConn holds the connection of a Management or Signal client and its
// service client C. A redial replaces both while streams and calls run, so read
// them with Conn and Client. The zero value holds no connection.
type RedialConn[C any] struct {
	mu        sync.RWMutex
	conn      *grpc.ClientConn
	client    C
	closed    bool
	keepalive time.Duration
	redialing atomic.Bool
}

// NewConnDial returns the dial of the component server at addr. It retries
// CreateConnection with Backoff, the sleeps wait on key. onDial, when set, gets
// the keepalive time of each dial before it starts.
func NewConnDial(component, addr string, tlsEnabled bool, key hbwatch.WaitKey, onDial func(time.Duration), opts ...grpc.DialOption) ConnDial {
	return func(ctx context.Context) (*grpc.ClientConn, time.Duration, error) {
		ka := KeepaliveTime(component, addr)
		if onDial != nil {
			onDial(ka)
		}
		var conn *grpc.ClientConn
		operation := func() error {
			var err error
			conn, err = CreateConnection(ctx, addr, tlsEnabled, component, opts...)
			if err != nil {
				return fmt.Errorf("create connection: %w", err)
			}
			return nil
		}
		if err := Retry(ctx, operation, Backoff(ctx), nil, key); err != nil {
			return nil, 0, err
		}
		return conn, ka, nil
	}
}

// LogStockDial notes a dial to the name server that uses the stock keepalive
// because the server answered stock earlier in this session. asked is whether
// the client asks for the aligned heartbeat. A stock answer on the new stream
// then finds the mark set and logs nothing.
func LogStockDial(name string, asked bool, ka time.Duration) {
	if asked && !AlignedKeepalive(ka) {
		log.Infof("%s answered stock earlier in this session, dialing with the stock keepalive", name)
	}
}

// Conn returns the current connection.
func (r *RedialConn[C]) Conn() *grpc.ClientConn {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.conn
}

// Client returns the service client of the current connection.
func (r *RedialConn[C]) Client() C {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.client
}

// Keepalive returns the keepalive time the current connection was dialed with.
func (r *RedialConn[C]) Keepalive() time.Duration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.keepalive
}

// Swap makes conn, with its service client and dialed with keepalive time ka,
// the connection unless Close ran. It returns the replaced connection, or
// swapped false after Close.
func (r *RedialConn[C]) Swap(conn *grpc.ClientConn, client C, ka time.Duration) (old *grpc.ClientConn, swapped bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, false
	}
	old = r.conn
	r.conn, r.client, r.keepalive = conn, client, ka
	return old, true
}

// Close closes the connection. A redial that finishes later closes its new
// connection instead of swapping it in.
func (r *RedialConn[C]) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	if r.conn == nil {
		return nil
	}
	return r.conn.Close()
}

// Ready checks that conn, the connection an attempt started with, can carry a
// stream to the name server. A connection a redial closed and replaced is a
// reason to retry on the new one; only a closed client ends the retry loop.
func (r *RedialConn[C]) Ready(ctx context.Context, conn *grpc.ClientConn, name string) error {
	name = strings.ToLower(name)
	connState := conn.GetState()
	log.Debugf("%s connection state %v", name, connState)
	if connState == connectivity.Shutdown {
		if conn != r.Conn() {
			return fmt.Errorf("%s connection replaced by a redial", name)
		}
		return backoff.Permanent(fmt.Errorf("connection to %s has been shut down", name))
	}
	if usable(connState) {
		return nil
	}
	// A dial may already be in flight, for example started by another stream
	// after a network change. Wait for it to settle instead of burning a
	// backoff round on a dial that succeeds.
	conn.WaitForStateChange(ctx, connState)
	if connState = conn.GetState(); !usable(connState) {
		return fmt.Errorf("connection to %s is not ready and in %s state", name, connState)
	}
	return nil
}

// StockAnswer marks the server of d stock for this session and redials a
// connection dialed with the aligned keepalive with the stock keepalive. The
// aligned keepalive pings too rarely for a server that sends no heartbeats.
// The redial follows the connection, not the mark: after a failed redial the
// next stock answer tries again. A connection that already uses the stock
// keepalive, as after an earlier mark that an aligned answer cleared, stays.
// added reports whether the mark is new: the server answered aligned, or not
// at all, since the last stock answer in this session.
func (r *RedialConn[C]) StockAnswer(ctx context.Context, d Redialer[C]) (added bool) {
	added = MarkStock(d.Component, d.Addr)
	if !AlignedKeepalive(r.Keepalive()) || d.Dial == nil {
		if added {
			log.Infof("%s answered stock, the stream runs stock", d.Name)
		}
		return added
	}
	if !r.redialing.CompareAndSwap(false, true) {
		return added
	}
	log.Infof("%s answered stock, redialing with the stock keepalive", d.Name)
	go func() {
		defer r.redialing.Store(false)
		r.redial(ctx, d)
	}()
	return added
}

// redial replaces the connection with a new one dialed with the keepalive the
// stock marks give now. The old connection is closed after the swap, so the
// stream loops reconnect on the new one.
func (r *RedialConn[C]) redial(ctx context.Context, d Redialer[C]) {
	conn, ka, err := d.Dial(ctx)
	if err != nil {
		log.Warnf("failed to redial %s with the stock keepalive: %v", d.Name, err)
		return
	}
	old, swapped := r.Swap(conn, d.NewClient(conn), ka)
	if !swapped {
		old = conn
	}
	if old == nil {
		return
	}
	if err := old.Close(); err != nil {
		log.Debugf("failed to close the %s connection left by the redial: %v", d.Name, err)
	}
}

func usable(s connectivity.State) bool {
	return s == connectivity.Ready || s == connectivity.Idle
}
