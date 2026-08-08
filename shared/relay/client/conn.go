package client

import (
	"net"
	"time"

	"github.com/netbirdio/netbird/shared/relay/messages"
)

// Conn represent a connection to a relayed remote peer.
type Conn struct {
	dstID       messages.PeerID
	messageChan chan Msg
	instanceURL *RelayAddr
	writeFn     func(messages.PeerID, []byte) (int, error)
	closeFn     func(messages.PeerID) error
	localAddrFn func() net.Addr
}

func (c *Conn) Write(p []byte) (n int, err error) {
	return c.writeFn(c.dstID, p)
}

func (c *Conn) Read(b []byte) (n int, err error) {
	m, ok := <-c.messageChan
	if !ok {
		return 0, net.ErrClosed
	}

	n = copy(b, m.Payload)
	m.Free()
	return n, nil
}

// BatchReader is an optional interface a net.Conn may implement to hand several
// relayed packets to the caller in one call. The relayed data path uses it to
// inject a whole batch into the local WireGuard socket with a single sendmmsg
// instead of one syscall per packet.
type BatchReader interface {
	// ReadBatch reads up to len(bufs) packets. It blocks for the first packet,
	// then drains any packets already queued without blocking. sizes[i] receives
	// the length copied into bufs[i]. It returns the number of packets read; a
	// return of (0, err) means the connection is closed.
	ReadBatch(bufs [][]byte, sizes []int) (n int, err error)
}

// ReadBatch implements BatchReader. It preserves Conn.Read's pooled-buffer
// contract: exactly one Msg is consumed and freed per packet returned, so it is
// safe to interleave with Read and with connContainer.close()'s drain loop.
func (c *Conn) ReadBatch(bufs [][]byte, sizes []int) (n int, err error) {
	if len(bufs) == 0 {
		return 0, nil
	}

	m, ok := <-c.messageChan
	if !ok {
		return 0, net.ErrClosed
	}
	sizes[0] = copy(bufs[0], m.Payload)
	m.Free()
	n = 1

	for n < len(bufs) {
		select {
		case m, ok = <-c.messageChan:
			if !ok {
				// Channel closed mid-drain: return what we have; the next
				// ReadBatch/Read observes the closed channel and errors.
				return n, nil
			}
			sizes[n] = copy(bufs[n], m.Payload)
			m.Free()
			n++
		default:
			return n, nil
		}
	}
	return n, nil
}

func (c *Conn) Close() error {
	return c.closeFn(c.dstID)
}

func (c *Conn) LocalAddr() net.Addr {
	return c.localAddrFn()
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.instanceURL
}

func (c *Conn) SetDeadline(t time.Time) error {
	//TODO implement me
	panic("SetDeadline is not implemented")
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	//TODO implement me
	panic("SetReadDeadline is not implemented")
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	//TODO implement me
	panic("SetReadDeadline is not implemented")
}
