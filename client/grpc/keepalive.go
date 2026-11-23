package grpc

import (
	"errors"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/shared/alignedhb/keepalive"
)

const (
	// stockKeepaliveTime is the gRPC keepalive ping time of clients without
	// the aligned heartbeat.
	stockKeepaliveTime = 30 * time.Second
	// keepaliveTimeout is how long a gRPC keepalive ping waits for its ack.
	keepaliveTimeout = 10 * time.Second
)

var (
	// clientPeriod returns the aligned heartbeat period this client asks for.
	// A var so tests can turn the request on outside mobile builds.
	clientPeriod = alignedhb.ClientPeriod

	// stockMarks holds the servers that answered stock in this session. A
	// client dials them with the stock keepalive.
	stockMarks = struct {
		sync.Mutex
		servers map[stockKey]struct{}
	}{servers: map[stockKey]struct{}{}}
)

// stockKey names one server: the service component, such as
// wsproxy.ManagementComponent, and its address. Management and Signal can
// share an address on a self-hosted setup but answer on their own.
type stockKey struct {
	component string
	addr      string
}

// TCPKeepAlive follows the TCP keepalive of the connection a gRPC client
// dialed to the aligned heartbeat answer of its stream. A new connection
// starts stock and an aligned answer switches it; it is never restored,
// because a client never opens a stock stream on a connection that carried
// an aligned one. The zero value is ready to use, and a nil *TCPKeepAlive
// does nothing.
type TCPKeepAlive struct {
	mu     sync.Mutex
	conn   net.Conn
	period time.Duration
}

// MarkStock records that the component server at addr answered the aligned
// heartbeat request stock. It reports whether the mark is new.
func MarkStock(component, addr string) (added bool) {
	stockMarks.Lock()
	defer stockMarks.Unlock()
	k := stockKey{component: component, addr: addr}
	if _, ok := stockMarks.servers[k]; ok {
		return false
	}
	stockMarks.servers[k] = struct{}{}
	return true
}

// ClearStock removes the mark of the component server at addr: the next dial
// uses the aligned keepalive again.
func ClearStock(component, addr string) {
	stockMarks.Lock()
	defer stockMarks.Unlock()
	delete(stockMarks.servers, stockKey{component: component, addr: addr})
}

// Track makes conn the connection to tune. It was dialed stock, and the
// stream that confirms the heartbeat on it has yet to open.
func (k *TCPKeepAlive) Track(conn net.Conn) {
	if k == nil {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.conn = conn
	k.period = 0
}

// SetAligned switches the current connection to the keepalive for heartbeats
// every period.
func (k *TCPKeepAlive) SetAligned(period time.Duration) {
	if k == nil || period <= 0 {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.conn == nil || k.period == period {
		return
	}
	err := keepalive.SetAligned(k.conn, period)
	switch {
	case errors.Is(err, keepalive.ErrNotTCP):
		return
	case err != nil:
		log.Debugf("failed to set TCP keepalive for heartbeat period %s: %v", period, err)
		return
	}
	k.period = period
}

// Applied returns the heartbeat period the keepalive of the current connection
// is set for, zero while it is stock.
func (k *TCPKeepAlive) Applied() time.Duration {
	if k == nil {
		return 0
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.period
}

func markedStock(component, addr string) bool {
	stockMarks.Lock()
	defer stockMarks.Unlock()
	_, ok := stockMarks.servers[stockKey{component: component, addr: addr}]
	return ok
}

// keepaliveTime returns the gRPC keepalive ping time for a dial to the
// component server at addr. It is fixed when the connection is dialed, before
// any server answer. A client that asks for the aligned heartbeat pings only
// after the receive timeout of its period, so a ping never lands between two
// heartbeats, unless that server answered stock in this session. Others keep
// the stock time.
func keepaliveTime(component, addr string) time.Duration {
	period, ok := clientPeriod()
	if !ok || markedStock(component, addr) {
		return stockKeepaliveTime
	}
	return alignedhb.ReceiveTimeout(period)
}

// alignedKeepalive reports whether d is longer than the stock keepalive time.
func alignedKeepalive(d time.Duration) bool {
	return d > stockKeepaliveTime
}
