package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/hbwatch"
	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/shared/alignedhb/keepalive"
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
	// encoder stamps the protocol version the relay selected for this connection.
	encoder messages.Encoder

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

	// alignedPeriod is the heartbeat period the server confirmed on this
	// connection in nanoseconds, zero while stock.
	alignedPeriod atomic.Int64
	// watchMu guards watchStop and watchEnded. watchStop unregisters the
	// hbwatch registration of this session, nil while unregistered.
	// watchEnded is set when the read loop exits, so a late registration
	// of an ended session does not stick.
	watchMu    sync.Mutex
	watchStop  func()
	watchEnded bool

	done chan struct{}
}

func newSession(c *Client, conn net.Conn, instanceURL *RelayAddr, transport string, encoder messages.Encoder) *session {
	s := &session{
		client:            c,
		log:               c.log.WithField("relay", instanceURL.String()),
		conn:              conn,
		instanceURL:       instanceURL,
		transport:         transport,
		encoder:           encoder,
		internallyStopped: newInternalStopFlag(),
		conns:             make(map[messages.PeerID]*connContainer),
		earlyMsgs:         newEarlyMsgBuffer(),
		done:              make(chan struct{}),
	}
	s.stateSubscription = NewPeersStateSubscription(s.log, conn, encoder, s.closeConnsByPeerID)
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

	if err := s.confirmContainer(peerID, container); err != nil {
		return nil, err
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

		err := messages.ValidateConnectionVersion(buf, s.encoder.Version())
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
	s.stopWatch()

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
		s.handleHealthCheck(buf)
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

func (s *session) handleHealthCheck(buf []byte) {
	s.switchAligned(buf)

	msg := s.encoder.Healthcheck()
	if period := s.answerPeriod(); period > 0 {
		msg = s.encoder.HealthcheckWithPeriod(uint16(period / time.Second))
	}
	_, wErr := s.conn.Write(msg)
	if wErr != nil {
		if !s.stopping() {
			s.log.Errorf("failed to send heartbeat: %s", wErr)
		}
	}
	s.hc.Heartbeat()
}

// askAligned asks for the aligned heartbeat right after the auth response,
// in the protocol version of this connection. A stock server ignores the
// payload and stays stock.
func (s *session) askAligned() {
	period, ok := s.client.askedPeriod()
	if !ok {
		return
	}
	if _, err := s.conn.Write(s.encoder.HealthcheckWithPeriod(uint16(period / time.Second))); err != nil {
		s.log.Debugf("failed to send aligned heartbeat request: %s", err)
	}
}

// answerPeriod returns the period a health check answer carries: the
// confirmed one once aligned, else the requested one, so a server that
// missed the first frame switches at a later answer. Zero keeps the stock
// frame.
func (s *session) answerPeriod() time.Duration {
	if period := s.confirmedPeriod(); period > 0 {
		return period
	}
	if period, ok := s.client.askedPeriod(); ok {
		return period
	}
	return 0
}

// confirmedPeriod returns the heartbeat period the server confirmed on this
// connection, zero while stock.
func (s *session) confirmedPeriod() time.Duration {
	return time.Duration(s.alignedPeriod.Load())
}

// switchAligned moves the receiver to the aligned timeout at the first
// server health check that carries a valid period, and records every
// aligned server frame with hbwatch while the session is registered. A
// payload of one byte or a period of zero stays stock.
func (s *session) switchAligned(buf []byte) {
	periodSeconds, ok, err := messages.UnmarshalHealthcheckPeriod(buf)
	if err != nil {
		s.log.Tracef("ignoring health check period: %s", err)
		return
	}
	if !ok {
		return
	}
	period := alignedhb.ClampPeriod(time.Duration(periodSeconds) * time.Second)
	if s.alignedPeriod.Swap(int64(period)) != int64(period) {
		s.hc.SetTimeout(alignedhb.ReceiveTimeout(period))
		if err := keepalive.SetAligned(s.conn, period); err != nil && !errors.Is(err, keepalive.ErrNotTCP) {
			s.log.Debugf("failed to set TCP keepalive for heartbeat period %s: %v", period, err)
		}
		phase := alignedhb.Phase(s.client.hashedID, period)
		s.log.Infof("aligned heartbeat on, period %s, phase %d ms", period, phase.Milliseconds())
	}

	// The period is stored before this check, so a registration racing the
	// frame either carries the period or is in place for Seen.
	s.watchMu.Lock()
	registered := s.watchStop != nil && !s.watchEnded
	s.watchMu.Unlock()
	if registered {
		hbwatch.Seen(hbwatch.Relay, period)
	}
}

// startWatch registers this session with hbwatch, unless it is registered
// already or its read loop has exited. The manager calls it only for the
// home session. The stale action closes the connection like a health check
// timeout.
func (s *session) startWatch() {
	// hbwatch never calls back into the relay client while it holds its
	// own lock, so registering under watchMu cannot deadlock.
	s.watchMu.Lock()
	defer s.watchMu.Unlock()
	if s.watchEnded || s.watchStop != nil {
		return
	}
	s.watchStop = hbwatch.Register(hbwatch.Relay, hbwatch.Registration{
		Kind:          hbwatch.ActionReconnect,
		Stale:         s.closeStale,
		Addr:          s.client.connectionURL,
		AlignedPeriod: s.confirmedPeriod(),
	})
}

// closeStale is the hbwatch stale action: it closes the connection like a
// health check timeout, and the read loop exit lets the guard reconnect.
func (s *session) closeStale() {
	s.log.Warnf("relay connection is stale, closing it like a health check timeout")
	s.internallyStopped.set()
	if err := s.conn.Close(); err != nil {
		s.log.Debugf("failed to close stale relay connection: %s", err)
	}
}

// stopWatch ends the hbwatch registration of this session, and blocks any
// later one. hbwatch ignores it once a newer session registered.
func (s *session) stopWatch() {
	s.watchMu.Lock()
	s.watchEnded = true
	stop := s.watchStop
	s.watchStop = nil
	s.watchMu.Unlock()
	if stop != nil {
		stop()
	}
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
	msg, err := messages.MarshalTransportMsg(s.encoder.Version(), dstID, payload)
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
		return 0, err
	}
	return len(payload), nil
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

func (s *session) confirmContainer(peerID messages.PeerID, container *connContainer) error {
	s.mu.Lock()
	closed := s.closed
	current := s.conns[peerID]
	s.mu.Unlock()

	if closed {
		container.close(ErrServerDisconnected)
		return fmt.Errorf("relay connection is not established")
	}
	if current != container {
		return fmt.Errorf("peer went offline while opening: %w", context.Cause(container.ctx))
	}
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
	msg := s.encoder.CloseMsg()
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
