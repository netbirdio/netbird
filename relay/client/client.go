package client

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	auth "github.com/netbirdio/netbird/relay/auth/hmac"
	"github.com/netbirdio/netbird/relay/client/dialer"
	"github.com/netbirdio/netbird/relay/client/dialer/quic"
	"github.com/netbirdio/netbird/relay/client/dialer/ws"
	"github.com/netbirdio/netbird/relay/healthcheck"
	"github.com/netbirdio/netbird/relay/messages"
)

const (
	bufferSize            = 8820
	serverResponseTimeout = 8 * time.Second
)

var (
	ErrConnAlreadyExists = fmt.Errorf("connection already exists")
)

type internalStopFlag struct {
	sync.Mutex
	stop bool
}

func newInternalStopFlag() *internalStopFlag {
	return &internalStopFlag{}
}

func (isf *internalStopFlag) set() {
	isf.Lock()
	defer isf.Unlock()
	isf.stop = true
}

func (isf *internalStopFlag) isSet() bool {
	isf.Lock()
	defer isf.Unlock()
	return isf.stop
}

// Msg carry the payload from the server to the client. With this struct, the net.Conn can free the buffer.
type Msg struct {
	Payload []byte

	bufPool *sync.Pool
	bufPtr  *[]byte
}

func (m *Msg) Free() {
	m.bufPool.Put(m.bufPtr)
}

// connContainer is a container for the connection to the peer. It is responsible for managing the messages from the
// server and forwarding them to the upper layer content reader.
type connContainer struct {
	log         *log.Entry
	conn        *Conn
	messages    chan Msg
	msgChanLock sync.Mutex
	closed      bool // flag to check if channel is closed
	ctx         context.Context
	cancel      context.CancelFunc
}

func newConnContainer(log *log.Entry, conn *Conn, messages chan Msg) *connContainer {
	ctx, cancel := context.WithCancel(context.Background())
	return &connContainer{
		log:      log,
		conn:     conn,
		messages: messages,
		ctx:      ctx,
		cancel:   cancel,
	}
}

func (cc *connContainer) writeMsg(msg Msg) {
	cc.msgChanLock.Lock()
	defer cc.msgChanLock.Unlock()

	if cc.closed {
		msg.Free()
		return
	}

	select {
	case cc.messages <- msg:
	case <-cc.ctx.Done():
		msg.Free()
	default:
		msg.Free()
	}
}

func (cc *connContainer) close() {
	cc.cancel()

	cc.msgChanLock.Lock()
	defer cc.msgChanLock.Unlock()

	if cc.closed {
		return
	}

	cc.closed = true
	close(cc.messages)

	for msg := range cc.messages {
		msg.Free()
	}
}

// Client is a client for the relay server. It is responsible for establishing a connection to the relay server and
// managing connections to other peers. All exported functions are safe to call concurrently. After close the connection,
// the client can be reused by calling Connect again. When the client is closed, all connections are closed too.
// While the Connect is in progress, the OpenConn function will block until the connection is established with relay server.
type Client struct {
	log            *log.Entry
	parentCtx      context.Context
	connectionURL  string
	authTokenStore *auth.TokenStore
	hashedID       messages.PeerID

	bufPool *sync.Pool

	relayConn        net.Conn
	conns            map[messages.PeerID]*connContainer
	serviceIsRunning bool
	mu               sync.Mutex // protect serviceIsRunning and conns
	readLoopMutex    sync.Mutex
	wgReadLoop       sync.WaitGroup
	instanceURL      *RelayAddr
	muInstanceURL    sync.Mutex

	onDisconnectListener func(string)
	listenerMutex        sync.Mutex

	stateSubscription *PeersStateSubscription
}

// NewClient creates a new client for the relay server. The client is not connected to the server until the Connect
func NewClient(ctx context.Context, serverURL string, authTokenStore *auth.TokenStore, peerID string) *Client {
	hashedID := messages.HashID(peerID)
	relayLog := log.WithFields(log.Fields{"relay": serverURL})

	c := &Client{
		log:            relayLog,
		parentCtx:      ctx,
		connectionURL:  serverURL,
		authTokenStore: authTokenStore,
		hashedID:       hashedID,
		bufPool: &sync.Pool{
			New: func() any {
				buf := make([]byte, bufferSize)
				return &buf
			},
		},
		conns: make(map[messages.PeerID]*connContainer),
	}

	c.log.Infof("create new relay connection: local peerID: %s, local peer hashedID: %s", peerID, hashedID)
	return c
}

// Connect establishes a connection to the relay server. It blocks until the connection is established or an error occurs.
func (c *Client) Connect() error {
	c.log.Infof("connecting to relay server")
	c.readLoopMutex.Lock()
	defer c.readLoopMutex.Unlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.serviceIsRunning {
		return nil
	}

	if err := c.connect(); err != nil {
		return err
	}

	c.stateSubscription = NewPeersStateSubscription(c.log, c.relayConn, c.closeConnsByPeerID)

	c.log = c.log.WithField("relay", c.instanceURL.String())
	c.log.Infof("relay connection established")

	c.serviceIsRunning = true

	c.wgReadLoop.Add(1)
	go c.readLoop(c.relayConn)

	return nil
}

// OpenConn create a new net.Conn for the destination peer ID. In case if the connection is in progress
// to the relay server, the function will block until the connection is established or timed out. Otherwise,
// it will return immediately.
// todo: what should happen if call with the same peerID with multiple times?
func (c *Client) OpenConn(dstPeerID string) (net.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.serviceIsRunning {
		return nil, fmt.Errorf("relay connection is not established")
	}

	peerID := messages.HashID(dstPeerID)
	_, ok := c.conns[peerID]
	if ok {
		return nil, ErrConnAlreadyExists
	}

	if err := c.stateSubscription.WaitToBeOnlineAndSubscribe(context.Background(), peerID); err != nil {
		c.log.Errorf("peer not available: %s, %s", peerID, err)
		return nil, err
	}

	c.log.Infof("open connection to peer: %s", peerID)
	msgChannel := make(chan Msg, 100)
	conn := NewConn(c, peerID, msgChannel, c.instanceURL)

	c.conns[peerID] = newConnContainer(c.log, conn, msgChannel)

	return conn, nil
}

// ServerInstanceURL returns the address of the relay server. It could change after the close and reopen the connection.
func (c *Client) ServerInstanceURL() (string, error) {
	c.muInstanceURL.Lock()
	defer c.muInstanceURL.Unlock()
	if c.instanceURL == nil {
		return "", fmt.Errorf("relay connection is not established")
	}
	return c.instanceURL.String(), nil
}

// SetOnDisconnectListener sets a function that will be called when the connection to the relay server is closed.
func (c *Client) SetOnDisconnectListener(fn func(string)) {
	c.listenerMutex.Lock()
	defer c.listenerMutex.Unlock()
	c.onDisconnectListener = fn
}

// HasConns returns true if there are connections.
func (c *Client) HasConns() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.conns) > 0
}

func (c *Client) Ready() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.serviceIsRunning
}

// Close closes the connection to the relay server and all connections to other peers.
func (c *Client) Close() error {
	return c.close(true)
}

func (c *Client) connect() error {
	rd := dialer.NewRaceDial(c.log, c.connectionURL, quic.Dialer{}, ws.Dialer{})
	conn, err := rd.Dial()
	if err != nil {
		return err
	}
	c.relayConn = conn

	if err = c.handShake(); err != nil {
		cErr := conn.Close()
		if cErr != nil {
			c.log.Errorf("failed to close connection: %s", cErr)
		}
		return err
	}

	return nil
}

func (c *Client) handShake() error {
	msg, err := messages.MarshalAuthMsg(c.hashedID, c.authTokenStore.TokenBinary())
	if err != nil {
		c.log.Errorf("failed to marshal auth message: %s", err)
		return err
	}

	_, err = c.relayConn.Write(msg)
	if err != nil {
		c.log.Errorf("failed to send auth message: %s", err)
		return err
	}
	buf := make([]byte, messages.MaxHandshakeRespSize)
	n, err := c.readWithTimeout(buf)
	if err != nil {
		c.log.Errorf("failed to read auth response: %s", err)
		return err
	}

	_, err = messages.ValidateVersion(buf[:n])
	if err != nil {
		return fmt.Errorf("validate version: %w", err)
	}

	msgType, err := messages.DetermineServerMessageType(buf[:n])
	if err != nil {
		c.log.Errorf("failed to determine message type: %s", err)
		return err
	}

	if msgType != messages.MsgTypeAuthResponse {
		c.log.Errorf("unexpected message type: %s", msgType)
		return fmt.Errorf("unexpected message type")
	}

	addr, err := messages.UnmarshalAuthResponse(buf[:n])
	if err != nil {
		return err
	}

	c.muInstanceURL.Lock()
	c.instanceURL = &RelayAddr{addr: addr}
	c.muInstanceURL.Unlock()
	return nil
}

func (c *Client) readLoop(relayConn net.Conn) {
	internallyStoppedFlag := newInternalStopFlag()
	hc := healthcheck.NewReceiver(c.log)
	go c.listenForStopEvents(hc, relayConn, internallyStoppedFlag)

	var (
		errExit error
		n       int
	)
	for {
		bufPtr := c.bufPool.Get().(*[]byte)
		buf := *bufPtr
		n, errExit = relayConn.Read(buf)
		if errExit != nil {
			c.log.Infof("start to Relay read loop exit")
			c.mu.Lock()
			if c.serviceIsRunning && !internallyStoppedFlag.isSet() {
				c.log.Errorf("failed to read message from relay server: %s", errExit)
			}
			c.mu.Unlock()
			c.bufPool.Put(bufPtr)
			break
		}

		buf = buf[:n]

		_, err := messages.ValidateVersion(buf)
		if err != nil {
			c.log.Errorf("failed to validate protocol version: %s", err)
			c.bufPool.Put(bufPtr)
			continue
		}

		msgType, err := messages.DetermineServerMessageType(buf)
		if err != nil {
			c.log.Errorf("failed to determine message type: %s", err)
			c.bufPool.Put(bufPtr)
			continue
		}

		if !c.handleMsg(msgType, buf, bufPtr, hc, internallyStoppedFlag) {
			break
		}
	}

	hc.Stop()

	c.muInstanceURL.Lock()
	c.instanceURL = nil
	c.muInstanceURL.Unlock()

	c.stateSubscription.Cleanup()
	c.wgReadLoop.Done()
	_ = c.close(false)
	c.notifyDisconnected()
}

func (c *Client) handleMsg(msgType messages.MsgType, buf []byte, bufPtr *[]byte, hc *healthcheck.Receiver, internallyStoppedFlag *internalStopFlag) (continueLoop bool) {
	switch msgType {
	case messages.MsgTypeHealthCheck:
		c.handleHealthCheck(hc, internallyStoppedFlag)
		c.bufPool.Put(bufPtr)
	case messages.MsgTypeTransport:
		return c.handleTransportMsg(buf, bufPtr, internallyStoppedFlag)
	case messages.MsgTypePeersOnline:
		peersID, err := messages.UnmarshalPeersOnlineMsg(buf)
		if err != nil {
			c.log.Errorf("failed to unmarshal peers online msg: %s", err)
			return true
		}
		c.stateSubscription.OnPeersOnline(peersID)
		return true
	case messages.MsgTypePeersWentOffline:
		peersID, err := messages.UnMarshalPeersWentOffline(buf)
		if err != nil {
			c.log.Errorf("failed to unmarshal peers online msg: %s", err)
			return true
		}
		c.stateSubscription.OnPeersWentOffline(peersID)
		return true
	case messages.MsgTypeClose:
		c.log.Debugf("relay connection close by server")
		c.bufPool.Put(bufPtr)
		return false
	}

	return true
}

func (c *Client) handleHealthCheck(hc *healthcheck.Receiver, internallyStoppedFlag *internalStopFlag) {
	msg := messages.MarshalHealthcheck()
	_, wErr := c.relayConn.Write(msg)
	if wErr != nil {
		if c.serviceIsRunning && !internallyStoppedFlag.isSet() {
			c.log.Errorf("failed to send heartbeat: %s", wErr)
		}
	}
	hc.Heartbeat()
}

func (c *Client) handleTransportMsg(buf []byte, bufPtr *[]byte, internallyStoppedFlag *internalStopFlag) bool {
	peerID, payload, err := messages.UnmarshalTransportMsg(buf)
	if err != nil {
		if c.serviceIsRunning && !internallyStoppedFlag.isSet() {
			c.log.Errorf("failed to parse transport message: %v", err)
		}

		c.bufPool.Put(bufPtr)
		return true
	}

	c.mu.Lock()
	if !c.serviceIsRunning {
		c.mu.Unlock()
		c.bufPool.Put(bufPtr)
		return false
	}
	container, ok := c.conns[*peerID]
	c.mu.Unlock()
	if !ok {
		c.log.Errorf("peer not found: %s", peerID.String())
		c.bufPool.Put(bufPtr)
		return true
	}
	msg := Msg{
		bufPool: c.bufPool,
		bufPtr:  bufPtr,
		Payload: payload,
	}
	container.writeMsg(msg)
	return true
}

func (c *Client) writeTo(connReference *Conn, dstID messages.PeerID, payload []byte) (int, error) {
	c.mu.Lock()
	conn, ok := c.conns[dstID]
	c.mu.Unlock()
	if !ok {
		return 0, net.ErrClosed
	}

	if conn.conn != connReference {
		return 0, net.ErrClosed
	}

	// todo: use buffer pool instead of create new transport msg.
	msg, err := messages.MarshalTransportMsg(dstID, payload)
	if err != nil {
		c.log.Errorf("failed to marshal transport message: %s", err)
		return 0, err
	}

	// the write always return with 0 length because the underling does not support the size feedback.
	_, err = c.relayConn.Write(msg)
	if err != nil {
		c.log.Errorf("failed to write transport message: %s", err)
	}
	return len(payload), err
}

func (c *Client) listenForStopEvents(hc *healthcheck.Receiver, conn net.Conn, internalStopFlag *internalStopFlag) {
	for {
		select {
		case _, ok := <-hc.OnTimeout:
			if !ok {
				return
			}
			c.log.Errorf("health check timeout")
			internalStopFlag.set()
			if err := conn.Close(); err != nil {
				// ignore the err handling because the readLoop will handle it
				c.log.Warnf("failed to close connection: %s", err)
			}
			return
		case <-c.parentCtx.Done():
			err := c.close(true)
			if err != nil {
				c.log.Errorf("failed to teardown connection: %s", err)
			}
			return
		}
	}
}

func (c *Client) closeAllConns() {
	for _, container := range c.conns {
		container.close()
	}
	c.conns = make(map[messages.PeerID]*connContainer)
}

func (c *Client) closeConnsByPeerID(peerIDs []messages.PeerID) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, peerID := range peerIDs {
		container, ok := c.conns[peerID]
		if !ok {
			c.log.Warnf("can not close conenction, peer not found: %s", peerID)
			continue
		}

		container.log.Infof("remote peer has been disconnected, free up connection: %s", peerID)
		container.close()
		delete(c.conns, peerID)
	}

	if err := c.stateSubscription.UnsubscribeStateChange(peerIDs); err != nil {
		c.log.Errorf("failed to unsubscribe from peer state change: %s, %s", peerIDs, err)
	}
	return
}

func (c *Client) closeConn(connReference *Conn, id messages.PeerID) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	container, ok := c.conns[id]
	if !ok {
		return net.ErrClosed
	}

	if container.conn != connReference {
		return fmt.Errorf("conn reference mismatch")
	}

	if err := c.stateSubscription.UnsubscribeStateChange([]messages.PeerID{id}); err != nil {
		container.log.Errorf("failed to unsubscribe from peer state change: %s", err)
	}

	c.log.Infof("free up connection to peer: %s", id)
	delete(c.conns, id)
	container.close()

	return nil
}

func (c *Client) close(gracefullyExit bool) error {
	c.readLoopMutex.Lock()
	defer c.readLoopMutex.Unlock()

	c.mu.Lock()
	var err error
	if !c.serviceIsRunning {
		c.mu.Unlock()
		c.log.Warn("relay connection was already marked as not running")
		return nil
	}

	c.serviceIsRunning = false
	c.log.Infof("closing all peer connections")
	c.closeAllConns()
	if gracefullyExit {
		c.writeCloseMsg()
	}
	err = c.relayConn.Close()
	c.mu.Unlock()

	c.log.Infof("waiting for read loop to close")
	c.wgReadLoop.Wait()
	c.log.Infof("relay connection closed")
	return err
}

func (c *Client) notifyDisconnected() {
	c.listenerMutex.Lock()
	defer c.listenerMutex.Unlock()

	if c.onDisconnectListener == nil {
		return
	}
	go c.onDisconnectListener(c.connectionURL)
}

func (c *Client) writeCloseMsg() {
	msg := messages.MarshalCloseMsg()
	_, err := c.relayConn.Write(msg)
	if err != nil {
		c.log.Errorf("failed to send close message: %s", err)
	}
}

func (c *Client) readWithTimeout(buf []byte) (int, error) {
	ctx, cancel := context.WithTimeout(c.parentCtx, serverResponseTimeout)
	defer cancel()

	readDone := make(chan struct{})
	var (
		n   int
		err error
	)

	go func() {
		n, err = c.relayConn.Read(buf)
		close(readDone)
	}()

	select {
	case <-ctx.Done():
		return 0, fmt.Errorf("read operation timed out")
	case <-readDone:
		return n, err
	}
}
