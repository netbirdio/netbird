package client

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/relay/client/dialer/udp"
	"github.com/netbirdio/netbird/relay/messages"
)

const (
	bufferSize            = 1500 // optimise the buffer size
	serverResponseTimeout = 8 * time.Second
)

type Msg struct {
	buf []byte
}

type connContainer struct {
	conn     *Conn
	messages chan Msg
}

// Client is a client for the relay server. It is responsible for establishing a connection to the relay server and
// managing connections to other peers. All exported functions are safe to call concurrently. After close the connection,
// the client can be reused by calling Connect again. When the client is closed, all connections are closed too.
// While the Connect is in progress, the OpenConn function will block until the connection is established.
type Client struct {
	log           *log.Entry
	parentCtx     context.Context
	ctx           context.Context
	ctxCancel     context.CancelFunc
	serverAddress string
	hashedID      []byte

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
		conns:         make(map[string]*connContainer),
	}
}

// SetOnDisconnectListener sets a function that will be called when the connection to the relay server is closed.
func (c *Client) SetOnDisconnectListener(fn func()) {
	c.listenerMutex.Lock()
	defer c.listenerMutex.Unlock()
	c.onDisconnectListener = fn
}

// Connect establishes a connection to the relay server. It blocks until the connection is established or an error occurs.
func (c *Client) Connect() error {
	c.readLoopMutex.Lock()
	defer c.readLoopMutex.Unlock()

	c.mu.Lock()

	if c.serviceIsRunning {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	err := c.connect()
	if err != nil {
		c.mu.Unlock()
		return err
	}

	c.serviceIsRunning = true

	c.ctx, c.ctxCancel = context.WithCancel(c.parentCtx)
	context.AfterFunc(c.ctx, func() {
		cErr := c.Close()
		if cErr != nil {
			log.Errorf("failed to close relay connection: %s", cErr)
		}
	})
	c.wgReadLoop.Add(1)
	go c.readLoop(c.relayConn)

	return nil
}

// todo: what should happen of call with the same peerID?
func (c *Client) OpenConn(dstPeerID string) (net.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.serviceIsRunning {
		return nil, fmt.Errorf("relay connection is not established")
	}

	hashedID, hashedStringID := messages.HashID(dstPeerID)
	log.Infof("open connection to peer: %s", hashedStringID)
	messageBuffer := make(chan Msg, 2)
	conn := NewConn(c, hashedID, hashedStringID, c.generateConnReaderFN(messageBuffer))

	c.conns[hashedStringID] = &connContainer{
		conn,
		messageBuffer,
	}
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

// Close closes the connection to the relay server and all connections to other peers.
func (c *Client) Close() error {
	c.readLoopMutex.Lock()
	defer c.readLoopMutex.Unlock()

	c.mu.Lock()
	var err error
	if c.serviceIsRunning {
		c.serviceIsRunning = false
		err = c.relayConn.Close()
	}
	c.closeAllConns()
	c.mu.Unlock()

	c.wgReadLoop.Wait()
	c.ctxCancel()
	return err
}

func (c *Client) connect() error {
	conn, err := udp.Dial(c.serverAddress)
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
	var errExit error
	var n int
	for {
		buf := make([]byte, bufferSize)
		n, errExit = relayConn.Read(buf)
		if errExit != nil {
			c.mu.Lock()
			if c.serviceIsRunning {
				c.log.Debugf("failed to read message from relay server: %s", errExit)
			}
			c.mu.Unlock()
			break
		}

		msgType, err := messages.DetermineServerMsgType(buf[:n])
		if err != nil {
			c.log.Errorf("failed to determine message type: %s", err)
			continue
		}

		switch msgType {
		case messages.MsgTypeTransport:
			peerID, err := messages.UnmarshalTransportID(buf[:n])
			if err != nil {
				c.log.Errorf("failed to parse transport message: %v", err)
				continue
			}
			stringID := messages.HashIDToString(peerID)

			c.mu.Lock()
			if !c.serviceIsRunning {
				c.mu.Unlock()
				break
			}
			container, ok := c.conns[stringID]
			c.mu.Unlock()
			if !ok {
				c.log.Errorf("peer not found: %s", stringID)
				continue
			}

			container.messages <- Msg{buf[:n]}
		}
	}

	c.notifyDisconnected()

	c.log.Tracef("exit from read loop")
	c.wgReadLoop.Done()

	c.Close()
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
	msg := messages.MarshalTransportMsg(dstID, payload)
	n, err := c.relayConn.Write(msg)
	if err != nil {
		log.Errorf("failed to write transport message: %s", err)
	}
	return n, err
}

func (c *Client) generateConnReaderFN(msgChannel chan Msg) func(b []byte) (n int, err error) {
	return func(b []byte) (n int, err error) {
		msg, ok := <-msgChannel
		if !ok {
			return 0, io.EOF
		}

		payload, err := messages.UnmarshalTransportPayload(msg.buf)
		if err != nil {
			return 0, err
		}

		n = copy(b, payload)
		return n, nil
	}
}

func (c *Client) closeAllConns() {
	for _, container := range c.conns {
		close(container.messages)
	}
	c.conns = make(map[string]*connContainer)
}

// todo check by reference too, the id is not enought because the id come from the outer conn
func (c *Client) closeConn(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	conn, ok := c.conns[id]
	if !ok {
		return fmt.Errorf("connection already closed")
	}
	close(conn.messages)
	delete(c.conns, id)

	return nil
}

func (c *Client) onDisconnect() {
	c.listenerMutex.Lock()
	defer c.listenerMutex.Unlock()

	if c.onDisconnectListener == nil {
		return
	}
	c.onDisconnectListener()
}

func (c *Client) notifyDisconnected() {
	c.listenerMutex.Lock()
	defer c.listenerMutex.Unlock()

	if c.onDisconnectListener == nil {
		return
	}
	go c.onDisconnectListener()
}
