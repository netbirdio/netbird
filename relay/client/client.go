package client

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	ws "github.com/netbirdio/netbird/relay/client/dialer/wsnhooyr"
	"github.com/netbirdio/netbird/relay/messages"
)

const (
	bufferSize            = 8820
	serverResponseTimeout = 8 * time.Second
)

var (
	ErrConnAlreadyExists = fmt.Errorf("connection already exists")
)

// Msg carry the payload from the server to the client. With this sturct, the net.Conn can free the buffer.
type Msg struct {
	Payload []byte

	bufPool *sync.Pool
	bufPtr  *[]byte
}

func (m *Msg) Free() {
	m.bufPool.Put(m.bufPtr)
}

type connContainer struct {
	conn        *Conn
	messages    chan Msg
	msgChanLock sync.Mutex
	closed      bool // flag to check if channel is closed
}

func newConnContainer(conn *Conn, messages chan Msg) *connContainer {
	return &connContainer{
		conn:     conn,
		messages: messages,
	}
}

func (cc *connContainer) writeMsg(msg Msg) {
	cc.msgChanLock.Lock()
	defer cc.msgChanLock.Unlock()
	if cc.closed {
		return
	}
	cc.messages <- msg
}

func (cc *connContainer) close() {
	cc.msgChanLock.Lock()
	defer cc.msgChanLock.Unlock()
	if cc.closed {
		return
	}
	close(cc.messages)
	cc.closed = true
}

// Client is a client for the relay server. It is responsible for establishing a connection to the relay server and
// managing connections to other peers. All exported functions are safe to call concurrently. After close the connection,
// the client can be reused by calling Connect again. When the client is closed, all connections are closed too.
// While the Connect is in progress, the OpenConn function will block until the connection is established.
type Client struct {
	log           *log.Entry
	parentCtx     context.Context
	ctxCancel     context.CancelFunc
	serverAddress string
	hashedID      []byte

	bufPool *sync.Pool

	relayConn        net.Conn
	conns            map[string]*connContainer
	serviceIsRunning bool
	mu               sync.Mutex
	readLoopMutex    sync.Mutex
	wgReadLoop       sync.WaitGroup

	remoteAddr net.Addr

	onDisconnectListener func()
	listenerMutex        sync.Mutex
}

// NewClient creates a new client for the relay server. The client is not connected to the server until the Connect
func NewClient(ctx context.Context, serverAddress, peerID string) *Client {
	hashedID, hashedStringId := messages.HashID(peerID)
	return &Client{
		log:           log.WithField("client_id", hashedStringId),
		parentCtx:     ctx,
		ctxCancel:     func() {},
		serverAddress: serverAddress,
		hashedID:      hashedID,
		bufPool: &sync.Pool{
			New: func() any {
				buf := make([]byte, bufferSize)
				return &buf
			},
		},
		conns: make(map[string]*connContainer),
	}
}

// Connect establishes a connection to the relay server. It blocks until the connection is established or an error occurs.
func (c *Client) Connect() error {
	c.log.Infof("connecting to relay server: %s", c.serverAddress)
	c.readLoopMutex.Lock()
	defer c.readLoopMutex.Unlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.serviceIsRunning {
		return nil
	}

	err := c.connect()
	if err != nil {
		return err
	}

	c.serviceIsRunning = true

	var ctx context.Context
	ctx, c.ctxCancel = context.WithCancel(c.parentCtx)
	context.AfterFunc(ctx, func() {
		cErr := c.close(false)
		if cErr != nil {
			log.Errorf("failed to close relay connection: %s", cErr)
		}
	})
	c.wgReadLoop.Add(1)
	go c.readLoop(c.relayConn)

	log.Infof("relay connection established with: %s", c.serverAddress)
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

	hashedID, hashedStringID := messages.HashID(dstPeerID)
	_, ok := c.conns[hashedStringID]
	if ok {
		return nil, ErrConnAlreadyExists
	}

	log.Infof("open connection to peer: %s", hashedStringID)
	msgChannel := make(chan Msg, 2)
	conn := NewConn(c, hashedID, hashedStringID, msgChannel)

	c.conns[hashedStringID] = newConnContainer(conn, msgChannel)
	return conn, nil
}

// RelayRemoteAddress returns the IP address of the relay server. It could change after the close and reopen the connection.
func (c *Client) RelayRemoteAddress() (net.Addr, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.remoteAddr == nil {
		return nil, fmt.Errorf("relay connection is not established")
	}
	return c.remoteAddr, nil
}

// SetOnDisconnectListener sets a function that will be called when the connection to the relay server is closed.
func (c *Client) SetOnDisconnectListener(fn func()) {
	c.listenerMutex.Lock()
	defer c.listenerMutex.Unlock()
	c.onDisconnectListener = fn
}

func (c *Client) HasConns() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.conns) > 0
}

// Close closes the connection to the relay server and all connections to other peers.
func (c *Client) Close() error {
	return c.close(false)
}

func (c *Client) close(byServer bool) error {
	c.readLoopMutex.Lock()
	defer c.readLoopMutex.Unlock()

	c.mu.Lock()
	var err error
	if !c.serviceIsRunning {
		c.mu.Unlock()
		return nil
	}

	c.serviceIsRunning = false
	c.closeAllConns()
	if !byServer {
		c.writeCloseMsg()
		err = c.relayConn.Close()
	}
	c.mu.Unlock()

	c.wgReadLoop.Wait()
	c.log.Infof("relay connection closed with: %s", c.serverAddress)
	c.ctxCancel()
	return err
}

func (c *Client) connect() error {
	conn, err := ws.Dial(c.serverAddress)
	if err != nil {
		return err
	}
	c.relayConn = conn

	err = c.handShake()
	if err != nil {
		cErr := conn.Close()
		if cErr != nil {
			log.Errorf("failed to close connection: %s", cErr)
		}
		c.relayConn = nil
		return err
	}

	c.remoteAddr = conn.RemoteAddr()

	return nil
}

func (c *Client) handShake() error {
	defer func() {
		err := c.relayConn.SetReadDeadline(time.Time{})
		if err != nil {
			log.Errorf("failed to reset read deadline: %s", err)
		}
	}()

	msg, err := messages.MarshalHelloMsg(c.hashedID)
	if err != nil {
		log.Errorf("failed to marshal hello message: %s", err)
		return err
	}
	_, err = c.relayConn.Write(msg)
	if err != nil {
		log.Errorf("failed to send hello message: %s", err)
		return err
	}

	err = c.relayConn.SetReadDeadline(time.Now().Add(serverResponseTimeout))
	if err != nil {
		log.Errorf("failed to set read deadline: %s", err)
		return err
	}

	buf := make([]byte, 1500) // todo: optimise buffer size
	n, err := c.relayConn.Read(buf)
	if err != nil {
		log.Errorf("failed to read hello response: %s", err)
		return err
	}

	msgType, err := messages.DetermineServerMsgType(buf[:n])
	if err != nil {
		log.Errorf("failed to determine message type: %s", err)
		return err
	}

	if msgType != messages.MsgTypeHelloResponse {
		log.Errorf("unexpected message type: %s", msgType)
		return fmt.Errorf("unexpected message type")
	}
	return nil
}

func (c *Client) readLoop(relayConn net.Conn) {
	var (
		errExit        error
		n              int
		closedByServer bool
	)
	for {
		bufPtr := c.bufPool.Get().(*[]byte)
		buf := *bufPtr
		n, errExit = relayConn.Read(buf)
		if errExit != nil {
			c.mu.Lock()
			if c.serviceIsRunning {
				c.log.Debugf("failed to read message from relay server: %s", errExit)
			}
			c.mu.Unlock()
			goto Exit
		}

		msgType, err := messages.DetermineServerMsgType(buf[:n])
		if err != nil {
			c.log.Errorf("failed to determine message type: %s", err)
			continue
		}

		switch msgType {
		case messages.MsgTypeTransport:
			peerID, payload, err := messages.UnmarshalTransportMsg(buf[:n])
			if err != nil {
				c.log.Errorf("failed to parse transport message: %v", err)
				continue
			}
			stringID := messages.HashIDToString(peerID)

			c.mu.Lock()
			if !c.serviceIsRunning {
				c.mu.Unlock()
				goto Exit
			}
			container, ok := c.conns[stringID]
			c.mu.Unlock()
			if !ok {
				c.log.Errorf("peer not found: %s", stringID)
				continue
			}

			container.writeMsg(Msg{
				bufPool: c.bufPool,
				bufPtr:  bufPtr,
				Payload: payload})
		case messages.MsgClose:
			closedByServer = true
			log.Debugf("relay connection close by server")
			goto Exit
		}
	}

Exit:
	c.notifyDisconnected()
	c.wgReadLoop.Done()
	_ = c.close(closedByServer)
}

// todo check by reference too, the id is not enought because the id come from the outer conn
func (c *Client) writeTo(id string, dstID []byte, payload []byte) (int, error) {
	c.mu.Lock()
	//	conn, ok := c.conns[id]
	_, ok := c.conns[id]
	c.mu.Unlock()
	if !ok {
		return 0, io.EOF
	}
	/*
		if conn != clientRef {
			return 0, io.EOF
		}
	*/
	msg, err := messages.MarshalTransportMsg(dstID, payload)
	if err != nil {
		log.Errorf("failed to marshal transport message: %s", err)
		return 0, err
	}
	n, err := c.relayConn.Write(msg)
	if err != nil {
		log.Errorf("failed to write transport message: %s", err)
	}
	return n, err
}

func (c *Client) closeAllConns() {
	for _, container := range c.conns {
		container.close()
	}
	c.conns = make(map[string]*connContainer)
}

// todo check by reference too, the id is not enought because the id come from the outer conn
func (c *Client) closeConn(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	container, ok := c.conns[id]
	if !ok {
		return fmt.Errorf("connection already closed")
	}
	container.close()
	delete(c.conns, id)

	return nil
}

func (c *Client) notifyDisconnected() {
	c.listenerMutex.Lock()
	defer c.listenerMutex.Unlock()

	if c.onDisconnectListener == nil {
		return
	}
	go c.onDisconnectListener()
}

func (c *Client) writeCloseMsg() {
	msg := messages.MarshalCloseMsg()
	_, err := c.relayConn.Write(msg)
	if err != nil {
		c.log.Errorf("failed to send close message: %s", err)
	}
}
