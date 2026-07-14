package server

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/relay/metrics"
	"github.com/netbirdio/netbird/relay/server/listener"
	"github.com/netbirdio/netbird/relay/server/store"
	"github.com/netbirdio/netbird/shared/relay/healthcheck"
	"github.com/netbirdio/netbird/shared/relay/messages"
)

const (
	bufferSize = messages.MaxMessageSize

	// msgQueueSize bounds the per-peer write queue: enough to absorb
	// write-latency jitter of a congested destination (~2.2 MB worst case)
	// without letting a dead peer pin unbounded memory.
	msgQueueSize = 256

	errCloseConn = "failed to close connection to peer: %s"

	queueDropLogInterval = 5 * time.Second
)

// msgPool recycles read buffers whose ownership moves from a source peer's
// read loop to a destination peer's write queue.
var msgPool = sync.Pool{
	New: func() any {
		buf := make([]byte, bufferSize)
		return &buf
	},
}

// queuedMsg is a pooled buffer holding one relayed transport message.
type queuedMsg struct {
	bufPtr *[]byte
	n      int
}

// Peer represents a peer connection
type Peer struct {
	metrics  *metrics.Metrics
	log      *log.Entry
	id       messages.PeerID
	conn     listener.Conn
	connMu   sync.RWMutex
	store    *store.Store
	notifier *store.PeerNotifier

	ctx       context.Context
	ctxCancel context.CancelFunc

	// msgQueue decouples writes to this peer from the read loops of the
	// source peers: a slow or stalled destination only fills its own queue.
	msgQueue chan queuedMsg
	// lastQueueDropLog (unix nanos) rate-limits the queue-overflow warning
	// emitted by source peers forwarding to this peer.
	lastQueueDropLog atomic.Int64

	peersListener *store.Listener

	// between the online peer collection step and the notification sending should not be sent offline notifications from another thread
	notificationMutex sync.Mutex
}

// NewPeer creates a new Peer instance and prepare custom logging
func NewPeer(metrics *metrics.Metrics, id messages.PeerID, conn listener.Conn, store *store.Store, notifier *store.PeerNotifier) *Peer {
	ctx, cancel := context.WithCancel(context.Background())
	p := &Peer{
		metrics:   metrics,
		log:       log.WithField("peer_id", id.String()),
		id:        id,
		conn:      conn,
		store:     store,
		notifier:  notifier,
		ctx:       ctx,
		ctxCancel: cancel,
		msgQueue:  make(chan queuedMsg, msgQueueSize),
	}

	return p
}

// Work reads data from the connection
// It manages the protocol (healthcheck, transport, close). Read the message and determine the message type and handle
// the message accordingly.
func (p *Peer) Work() {
	p.peersListener = p.notifier.NewListener(p.sendPeersOnline, p.sendPeersWentOffline)
	defer func() {
		p.ctxCancel()
		p.notifier.RemoveListener(p.peersListener)

		if err := p.conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			p.log.Errorf(errCloseConn, err)
		}
	}()

	ctx := p.ctx

	hc := healthcheck.NewSender(p.log)
	go hc.StartHealthCheck(ctx)
	go p.handleHealthcheckEvents(ctx, hc)
	go p.writeLoop()

	for {
		bufPtr := msgPool.Get().(*[]byte)
		n, err := p.conn.Read(ctx, *bufPtr)
		if err != nil {
			msgPool.Put(bufPtr)
			if !errors.Is(err, net.ErrClosed) {
				p.log.Errorf("failed to read message: %s", err)
			}
			return
		}

		if n == 0 {
			msgPool.Put(bufPtr)
			p.log.Errorf("received empty message")
			return
		}

		msg := (*bufPtr)[:n]

		_, err = messages.ValidateVersion(msg)
		if err != nil {
			msgPool.Put(bufPtr)
			p.log.Warnf("failed to validate protocol version: %s", err)
			return
		}

		msgType, err := messages.DetermineClientMessageType(msg)
		if err != nil {
			msgPool.Put(bufPtr)
			p.log.Errorf("failed to determine message type: %s", err)
			return
		}

		if !p.handleMsgType(ctx, msgType, hc, n, bufPtr) {
			msgPool.Put(bufPtr)
		}
	}
}

func (p *Peer) ID() messages.PeerID {
	return p.id
}

// handleMsgType dispatches one inbound message. It reports whether ownership
// of bufPtr moved to a destination peer's write queue; when false the caller
// returns the buffer to the pool.
func (p *Peer) handleMsgType(ctx context.Context, msgType messages.MsgType, hc *healthcheck.Sender, n int, bufPtr *[]byte) bool {
	msg := (*bufPtr)[:n]
	switch msgType {
	case messages.MsgTypeHealthCheck:
		hc.OnHCResponse()
	case messages.MsgTypeTransport, messages.MsgTypeTransportBatch:
		// A batch frame shares the transport header (dest peerID at the fixed
		// offset); the relay only reads that header, rewrites it to the source,
		// and forwards the payload opaque, so both types route identically.
		p.metrics.TransferBytesRecv.Add(ctx, int64(n))
		p.metrics.PeerActivity(p.String())
		return p.handleTransportMsg(bufPtr, n)
	case messages.MsgTypeClose:
		p.log.Infof("peer exited gracefully")
		if err := p.conn.Close(); err != nil {
			log.Errorf(errCloseConn, err)
		}
	case messages.MsgTypeSubscribePeerState:
		p.handleSubscribePeerState(msg)
	case messages.MsgTypeUnsubscribePeerState:
		p.handleUnsubscribePeerState(msg)
	default:
		p.log.Warnf("received unexpected message type: %s", msgType)
	}
	return false
}

// Write writes data to the connection
func (p *Peer) Write(ctx context.Context, b []byte) (int, error) {
	p.connMu.RLock()
	defer p.connMu.RUnlock()
	return p.conn.Write(ctx, b)
}

// CloseGracefully closes the connection with the peer gracefully. Send a close message to the client and close the
// connection.
func (p *Peer) CloseGracefully(ctx context.Context) {
	p.connMu.Lock()
	defer p.connMu.Unlock()
	err := p.writeWithTimeout(ctx, messages.MarshalCloseMsg())
	if err != nil {
		p.log.Errorf("failed to send close message to peer: %s", p.String())
	}

	p.ctxCancel()
	if err := p.conn.Close(); err != nil {
		p.log.Errorf(errCloseConn, err)
	}
}

func (p *Peer) Close() {
	p.connMu.Lock()
	defer p.connMu.Unlock()

	p.ctxCancel()
	if err := p.conn.Close(); err != nil {
		p.log.Errorf(errCloseConn, err)
	}
}

// String returns the peer ID
func (p *Peer) String() string {
	return p.id.String()
}

func (p *Peer) writeWithTimeout(ctx context.Context, buf []byte) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	_, err := p.conn.Write(ctx, buf)
	return err
}

func (p *Peer) handleHealthcheckEvents(ctx context.Context, hc *healthcheck.Sender) {
	for {
		select {
		case <-hc.HealthCheck:
			_, err := p.Write(ctx, messages.MarshalHealthcheck())
			if err != nil {
				p.log.Errorf("failed to send healthcheck message: %s", err)
				return
			}
		case <-hc.Timeout:
			p.log.Errorf("peer healthcheck timeout")
			err := p.conn.Close()
			if err != nil {
				p.log.Errorf("failed to close connection to peer: %s", err)
			}
			p.log.Info("peer connection closed due healthcheck timeout")
			return
		case <-ctx.Done():
			return
		}
	}
}

// handleTransportMsg forwards one transport message by enqueueing it on the
// destination peer's write queue. It reports whether ownership of bufPtr moved
// to that queue. The enqueue never blocks: a full queue means the destination
// is congested or gone, and stalling this read loop would stall every flow of
// the source peer.
func (p *Peer) handleTransportMsg(bufPtr *[]byte, n int) bool {
	msg := (*bufPtr)[:n]
	peerID, err := messages.UnmarshalTransportID(msg)
	if err != nil {
		p.log.Errorf("failed to unmarshal transport message: %s", err)
		return false
	}

	item, ok := p.store.Peer(*peerID)
	if !ok {
		p.log.Debugf("peer not found: %s", peerID)
		return false
	}
	dp := item.(*Peer)

	if err := messages.UpdateTransportMsg(msg, p.id); err != nil {
		p.log.Errorf("failed to update transport message: %s", err)
		return false
	}

	select {
	case dp.msgQueue <- queuedMsg{bufPtr: bufPtr, n: n}:
		return true
	default:
		p.metrics.TransportQueueDrop(dp.conn.Protocol())
		now := time.Now().UnixNano()
		last := dp.lastQueueDropLog.Load()
		if now-last >= int64(queueDropLogInterval) && dp.lastQueueDropLog.CompareAndSwap(last, now) {
			p.log.Warnf("dropping transport message to %s: write queue full", dp.String())
		}
		return false
	}
}

// writeLoop serializes relayed transport writes to this peer so a slow
// destination only backs up its own queue, never a source's read loop.
// Control messages (healthcheck, peer notifications, close) keep writing
// directly, as before.
func (p *Peer) writeLoop() {
	defer p.drainQueue()
	for {
		select {
		case <-p.ctx.Done():
			return
		case m := <-p.msgQueue:
			// Write on the conn directly, not via p.Write: holding connMu.RLock
			// while a stalled destination blocks the write would deadlock
			// Close(), which needs connMu.Lock to close the very conn that
			// unblocks the write. Both conn implementations serialize
			// concurrent writes and tolerate a concurrent Close.
			n, err := p.conn.Write(p.ctx, (*m.bufPtr)[:m.n])
			msgPool.Put(m.bufPtr)
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					p.log.Errorf("failed to write transport message: %s", err)
				}
				continue
			}
			p.metrics.TransferBytesSent.Add(p.ctx, int64(n))
		}
	}
}

// drainQueue returns queued buffers to the pool after the writer stopped.
func (p *Peer) drainQueue() {
	for {
		select {
		case m := <-p.msgQueue:
			msgPool.Put(m.bufPtr)
		default:
			return
		}
	}
}

func (p *Peer) handleSubscribePeerState(msg []byte) {
	peerIDs, err := messages.UnmarshalSubPeerStateMsg(msg)
	if err != nil {
		p.log.Errorf("failed to unmarshal open connection message: %s", err)
		return
	}

	p.log.Debugf("received subscription message for %d peers", len(peerIDs))

	// collect online peers to response back to the caller
	p.notificationMutex.Lock()
	defer p.notificationMutex.Unlock()

	onlinePeers := p.store.GetOnlinePeersAndRegisterInterest(peerIDs, p.peersListener)
	if len(onlinePeers) == 0 {
		return
	}

	p.log.Debugf("response with %d online peers", len(onlinePeers))
	p.sendPeersOnline(onlinePeers)
}

func (p *Peer) handleUnsubscribePeerState(msg []byte) {
	peerIDs, err := messages.UnmarshalUnsubPeerStateMsg(msg)
	if err != nil {
		p.log.Errorf("failed to unmarshal open connection message: %s", err)
		return
	}

	p.peersListener.RemoveInterestedPeer(peerIDs)
}

func (p *Peer) sendPeersOnline(peers []messages.PeerID) {
	msgs, err := messages.MarshalPeersOnline(peers)
	if err != nil {
		p.log.Errorf("failed to marshal peer location message: %s", err)
		return
	}

	for n, msg := range msgs {
		if _, err := p.Write(p.ctx, msg); err != nil {
			p.log.Errorf("failed to write %d. peers offline message: %s", n, err)
		}
	}
}

func (p *Peer) sendPeersWentOffline(peers []messages.PeerID) {
	p.notificationMutex.Lock()
	defer p.notificationMutex.Unlock()

	msgs, err := messages.MarshalPeersWentOffline(peers)
	if err != nil {
		p.log.Errorf("failed to marshal peer location message: %s", err)
		return
	}

	for n, msg := range msgs {
		if _, err := p.Write(p.ctx, msg); err != nil {
			p.log.Errorf("failed to write %d. peers offline message: %s", n, err)
		}
	}
}
