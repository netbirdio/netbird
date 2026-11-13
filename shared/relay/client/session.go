package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	log "github.com/sirupsen/logrus"

	netErr "github.com/netbirdio/netbird/shared/relay/client/dialer/net"
	"github.com/netbirdio/netbird/shared/relay/healthcheck"
	"github.com/netbirdio/netbird/shared/relay/messages"
)

// session is one established connection to a relay server, from the handshake
// until that connection ends. It owns everything bound to the connection: the
// read loop, the relayed peer connections, the early message buffer, the peer
// state subscription and the healthcheck. A session is never reused; the Client
// creates a new one on every connect. Wait returns once the read loop has
// exited and the teardown has finished, also when it is called after the end.
type session struct {
	client *Client
	log    *log.Entry

	conn        net.Conn
	instanceURL *RelayAddr
	transport   string

	stateSubscription *PeersStateSubscription
	hc                *healthcheck.Receiver
	internallyStopped *internalStopFlag

	conns     map[messages.PeerID]*connContainer
	earlyMsgs *earlyMsgBuffer
	closed    bool
	mu        sync.Mutex // protect conns and closed
	closeOnce sync.Once

	// datagramFallbackTriggered guards a single fallback per connection so a
	// burst of oversized datagrams triggers one reconnect, not many.
	datagramFallbackTriggered atomic.Bool

	done chan struct{}
}

func newSession(c *Client, conn net.Conn, instanceURL *RelayAddr, transport string) *session {
	s := &session{
		client:            c,
		log:               c.log.WithField("relay", instanceURL.String()),
		conn:              conn,
		instanceURL:       instanceURL,
		transport:         transport,
		internallyStopped: newInternalStopFlag(),
		conns:             make(map[messages.PeerID]*connContainer),
		earlyMsgs:         newEarlyMsgBuffer(),
		done:              make(chan struct{}),
	}
	s.stateSubscription = NewPeersStateSubscription(s.log, conn, s.closeConnsByPeerID)
	s.hc = healthcheck.NewReceiver(s.log)
	return s
}

func (s *session) Wait(ctx context.Context) bool {
	select {
	case <-s.done:
		return true
	case <-ctx.Done():
		return false
	}
}

func (s *session) OpenConn(ctx context.Context, peerID messages.PeerID) (*Conn, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, fmt.Errorf("relay connection is not established")
	}
	_, ok := s.conns[peerID]
	if ok {
		s.mu.Unlock()
		return nil, ErrConnAlreadyExists
	}

	s.log.Infof("prepare the relayed connection, waiting for remote peer: %s", peerID)

	container := newConnContainer(s.log, s, peerID, s.instanceURL)
	s.conns[peerID] = container
	earlyMsg, hasEarly := s.earlyMsgs.pop(peerID)
	s.mu.Unlock()

	if hasEarly {
		container.writeMsg(earlyMsg)
		s.log.Tracef("flushed buffered early message for peer: %s", peerID)
	}

	if err := s.stateSubscription.WaitToBeOnlineAndSubscribe(ctx, peerID); err != nil {
		s.log.Errorf("peer not available: %s, %s", peerID, err)
		s.mu.Lock()
		if savedContainer, ok := s.conns[peerID]; ok && savedContainer == container {
			delete(s.conns, peerID)
		}
		s.mu.Unlock()
		container.close(err)
		return nil, err
	}

	if s.isClosed() {
		container.close(ErrServerDisconnected)
		return nil, fmt.Errorf("relay connection is not established")
	}

	s.log.Infof("remote peer is available: %s", peerID)
	return container.conn, nil
}

func (s *session) HasConns() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.conns) > 0
}

func (s *session) ReadLoop() {
	var (
		errExit error
		n       int
	)
	for {
		bufPtr := s.client.bufPool.Get().(*[]byte)
		buf := *bufPtr
		n, errExit = s.conn.Read(buf)
		if errExit != nil {
			s.log.Infof("start to Relay read loop exit")
			if !s.stopping() {
				s.log.Errorf("failed to read message from relay server: %s", errExit)
			}
			s.client.bufPool.Put(bufPtr)
			break
		}

		buf = buf[:n]

		_, err := messages.ValidateVersion(buf)
		if err != nil {
			s.log.Errorf("failed to validate protocol version: %s", err)
			s.client.bufPool.Put(bufPtr)
			continue
		}

		msgType, err := messages.DetermineServerMessageType(buf)
		if err != nil {
			s.log.Errorf("failed to determine message type: %s", err)
			s.client.bufPool.Put(bufPtr)
			continue
		}

		if !s.handleMsg(msgType, buf, bufPtr) {
			break
		}
	}

	s.hc.Stop()

	if err := s.Close(false); err != nil {
		s.log.Debugf("failed to close relay connection: %s", err)
	}
	s.stateSubscription.Cleanup()
	s.log.Infof("relay connection closed")
	close(s.done)
}

func (s *session) ListenForStopEvents(ctx context.Context) {
	for {
		select {
		case _, ok := <-s.hc.OnTimeout:
			if !ok {
				return
			}
			s.log.Errorf("health check timeout")
			s.internallyStopped.set()
			if err := s.conn.Close(); err != nil {
				// ignore the err handling because the readLoop will handle it
				s.log.Warnf("failed to close connection: %s", err)
			}
			return
		case <-ctx.Done():
			err := s.Close(true)
			if err != nil {
				s.log.Errorf("failed to teardown connection: %s", err)
			}
			return
		}
	}
}

func (s *session) Close(gracefullyExit bool) error {
	var err error
	s.closeOnce.Do(func() {
		err = s.teardown(gracefullyExit)
	})
	return err
}

func (s *session) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *session) stopping() bool {
	return s.isClosed() || s.internallyStopped.isSet()
}

func (s *session) handleMsg(msgType messages.MsgType, buf []byte, bufPtr *[]byte) (continueLoop bool) {
	switch msgType {
	case messages.MsgTypeHealthCheck:
		s.handleHealthCheck()
		s.client.bufPool.Put(bufPtr)
	case messages.MsgTypeTransport:
		return s.handleTransportMsg(buf, bufPtr)
	case messages.MsgTypePeersOnline:
		s.handlePeersOnlineMsg(buf)
		s.client.bufPool.Put(bufPtr)
		return true
	case messages.MsgTypePeersWentOffline:
		s.handlePeersWentOfflineMsg(buf)
		s.client.bufPool.Put(bufPtr)
		return true
	case messages.MsgTypeClose:
		s.log.Debugf("relay connection close by server")
		s.client.bufPool.Put(bufPtr)
		return false
	}

	return true
}

func (s *session) handleHealthCheck() {
	msg := messages.MarshalHealthcheck()
	_, wErr := s.conn.Write(msg)
	if wErr != nil {
		if !s.stopping() {
			s.log.Errorf("failed to send heartbeat: %s", wErr)
		}
	}
	s.hc.Heartbeat()
}

func (s *session) handleTransportMsg(buf []byte, bufPtr *[]byte) bool {
	peerID, payload, err := messages.UnmarshalTransportMsg(buf)
	if err != nil {
		if !s.stopping() {
			s.log.Errorf("failed to parse transport message: %v", err)
		}

		s.client.bufPool.Put(bufPtr)
		return true
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		s.client.bufPool.Put(bufPtr)
		return false
	}
	container, ok := s.conns[*peerID]
	s.mu.Unlock()
	if !ok {
		msg := Msg{
			bufPool: s.client.bufPool,
			bufPtr:  bufPtr,
			Payload: payload,
		}
		if !s.earlyMsgs.put(*peerID, msg) {
			s.log.Warnf("failed to buffer early message for peer: %s", peerID.String())
			s.client.bufPool.Put(bufPtr)
		} else {
			s.log.Debugf("buffered early transport message for peer: %s", peerID.String())
		}
		return true
	}
	msg := Msg{
		bufPool: s.client.bufPool,
		bufPtr:  bufPtr,
		Payload: payload,
	}
	container.writeMsg(msg)
	return true
}

func (s *session) writeTo(containerRef *connContainer, dstID messages.PeerID, payload []byte) (int, error) {
	s.mu.Lock()
	current, ok := s.conns[dstID]
	s.mu.Unlock()
	if !ok {
		return 0, net.ErrClosed
	}

	if current != containerRef {
		return 0, net.ErrClosed
	}

	// todo: use buffer pool instead of create new transport msg.
	msg, err := messages.MarshalTransportMsg(dstID, payload)
	if err != nil {
		s.log.Errorf("failed to marshal transport message: %s", err)
		return 0, err
	}

	// the write always return with 0 length because the underling does not support the size feedback.
	_, err = s.conn.Write(msg)
	if err != nil {
		if errors.Is(err, netErr.ErrDatagramTooLarge) {
			s.onDatagramTooLarge(err)
		} else {
			s.log.Errorf("failed to write transport message: %s", err)
		}
	}
	return len(payload), err
}

// onDatagramTooLarge reacts to a datagram rejected as too large for the path.
// When a non-datagram transport is available, it records a fallback for this
// server and closes the connection so the reconnect avoids datagram-sized
// transports. A single fallback is triggered per connection regardless of how
// many oversized datagrams arrive. cause carries the datagram size and budget.
func (s *session) onDatagramTooLarge(cause error) {
	// Handle one oversized datagram per connection; a burst triggers a single
	// fallback (and a single log line), not many.
	if !s.datagramFallbackTriggered.CompareAndSwap(false, true) {
		return
	}

	// If the selected mode offers no non-datagram transport (e.g. pinned to a
	// datagram-sized transport), reconnecting would just re-fail, so leave the
	// connection up rather than loop.
	if len(nonDatagramSized(s.client.baseDialers(transportModeFromEnv()))) == 0 {
		s.log.Warnf("%s, but no non-datagram transport is available, not falling back", cause)
		return
	}

	// Without the shared tracker a reconnect would just select the same
	// transport again and re-fail, so leave the connection up rather than loop.
	if s.client.transportFallback == nil {
		s.log.Debugf("%s, but no transport fallback configured, leaving connection up", cause)
		return
	}

	window := s.client.transportFallback.recordFailure(s.client.connectionURL)
	s.log.Warnf("%s, avoiding datagram-sized transport for %s", cause, window)

	if err := s.conn.Close(); err != nil {
		s.log.Debugf("close relay connection for transport fallback: %s", err)
	}
}

func (s *session) closeConnsByPeerID(peerIDs []messages.PeerID) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, peerID := range peerIDs {
		container, ok := s.conns[peerID]
		if !ok {
			s.log.Warnf("can not close connection, peer not found: %s", peerID)
			continue
		}

		container.log.Infof("remote peer has been disconnected, free up connection: %s", peerID)
		container.close(ErrPeerDisconnected)
		delete(s.conns, peerID)
	}

	if err := s.stateSubscription.UnsubscribeStateChange(peerIDs); err != nil {
		s.log.Errorf("failed to unsubscribe from peer state change: %s, %s", peerIDs, err)
	}
}

func (s *session) closeConn(containerRef *connContainer, id messages.PeerID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	current, ok := s.conns[id]
	if !ok {
		return net.ErrClosed
	}

	if current != containerRef {
		return fmt.Errorf("conn reference mismatch")
	}

	if err := s.stateSubscription.UnsubscribeStateChange([]messages.PeerID{id}); err != nil {
		current.log.Errorf("failed to unsubscribe from peer state change: %s", err)
	}

	s.log.Infof("free up connection to peer: %s", id)
	delete(s.conns, id)
	current.close(net.ErrClosed)

	return nil
}

func (s *session) teardown(gracefullyExit bool) error {
	s.client.DetachSession(s)

	s.mu.Lock()
	s.closed = true
	conns := s.conns
	s.conns = nil
	s.mu.Unlock()

	s.log.Infof("closing all peer connections")
	for _, container := range conns {
		container.close(ErrServerDisconnected)
	}
	s.earlyMsgs.close()

	if gracefullyExit {
		s.writeCloseMsg()
	}
	return s.conn.Close()
}

func (s *session) writeCloseMsg() {
	msg := messages.MarshalCloseMsg()
	_, err := s.conn.Write(msg)
	if err != nil {
		s.log.Errorf("failed to send close message: %s", err)
	}
}

func (s *session) handlePeersOnlineMsg(buf []byte) {
	peersID, err := messages.UnmarshalPeersOnlineMsg(buf)
	if err != nil {
		s.log.Errorf("failed to unmarshal peers online msg: %s", err)
		return
	}
	s.stateSubscription.OnPeersOnline(peersID)
}

func (s *session) handlePeersWentOfflineMsg(buf []byte) {
	peersID, err := messages.UnMarshalPeersWentOffline(buf)
	if err != nil {
		s.log.Errorf("failed to unmarshal peers went offline msg: %s", err)
		return
	}
	s.stateSubscription.OnPeersWentOffline(peersID)
}
