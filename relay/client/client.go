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

type bufMsg struct {
	bufPtr *[]byte
	buf    []byte
}

type connContainer struct {
	conn     *Conn
	messages chan bufMsg
}

// Client Todo:
// - handle automatic reconnection
type Client struct {
	serverAddress string
	peerID        string

	channelsPending map[string]chan net.Conn // todo: protect map with mutex
	channels        map[uint16]*connContainer
	msgPool         sync.Pool

	relayConn      net.Conn
	relayConnState bool
	mu             sync.Mutex
}

func NewClient(serverAddress, peerID string) *Client {
	return &Client{
		serverAddress:   serverAddress,
		peerID:          peerID,
		channelsPending: make(map[string]chan net.Conn),
		channels:        make(map[uint16]*connContainer),
		msgPool: sync.Pool{
			New: func() any {
				buf := make([]byte, bufferSize)
				return &buf
			},
		},
	}
}

func (c *Client) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()
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

	err = c.relayConn.SetReadDeadline(time.Time{})
	if err != nil {
		log.Errorf("failed to reset read deadline: %s", err)
		return err
	}

	c.relayConnState = true
	go c.readLoop()
	return nil
}

func (c *Client) BindChannel(remotePeerID string) (net.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.relayConn == nil {
		return nil, fmt.Errorf("client not connected to the relay server")
	}

	bindSuccessChan := make(chan net.Conn, 1)
	c.channelsPending[remotePeerID] = bindSuccessChan
	msg := messages.MarshalBindNewChannelMsg(remotePeerID)
	_, err := c.relayConn.Write(msg)
	if err != nil {
		log.Errorf("failed to write out bind message: %s", err)
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), serverResponseTimeout)
	defer cancel()
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("bind timeout")
	case c := <-bindSuccessChan:
		return c, nil
	}
}

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.relayConnState {
		return nil
	}

	for _, conn := range c.channels {
		close(conn.messages)
	}
	c.channels = make(map[uint16]*connContainer)
	c.relayConnState = false
	err := c.relayConn.Close()
	return err
}

func (c *Client) handShake() error {
	msg, err := messages.MarshalHelloMsg(c.peerID)
	if err != nil {
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

func (c *Client) readLoop() {
	log := log.WithField("client_id", c.peerID)
	var errExit error
	var n int
	for {
		bufPtr := c.msgPool.Get().(*[]byte)
		buf := *bufPtr
		n, errExit = c.relayConn.Read(buf)
		if errExit != nil {
			log.Debugf("failed to read message from relay server: %s", errExit)
			c.freeBuf(bufPtr)
			break
		}

		msgType, err := messages.DetermineServerMsgType(buf[:n])
		if err != nil {
			log.Errorf("failed to determine message type: %s", err)
			c.freeBuf(bufPtr)
			continue
		}

		switch msgType {
		case messages.MsgTypeBindResponse:
			channelId, peerId, err := messages.UnmarshalBindResponseMsg(buf[:n])
			if err != nil {
				log.Errorf("failed to parse bind response message: %v", err)
			} else {
				c.handleBindResponse(channelId, peerId)
			}
			c.freeBuf(bufPtr)
			continue
		case messages.MsgTypeTransport:
			channelId, err := messages.UnmarshalTransportID(buf[:n])
			if err != nil {
				log.Errorf("failed to parse transport message: %v", err)
				c.freeBuf(bufPtr)
				continue
			}
			container, ok := c.channels[channelId]
			if !ok {
				log.Errorf("unexpected transport message for channel: %d", channelId)
				c.freeBuf(bufPtr)
				return
			}

			container.messages <- bufMsg{
				bufPtr,
				buf[:n],
			}
		}
	}

	if c.relayConnState {
		log.Errorf("failed to read message from relay server: %s", errExit)
		_ = c.relayConn.Close()
	}
}

func (c *Client) handleBindResponse(channelId uint16, peerId string) {
	bindSuccessChan, ok := c.channelsPending[peerId]
	if !ok {
		log.Errorf("unexpected bind response from: %s", peerId)
		return
	}
	delete(c.channelsPending, peerId)

	messageBuffer := make(chan bufMsg, 2)
	conn := NewConn(c, channelId, c.generateConnReaderFN(messageBuffer))

	c.channels[channelId] = &connContainer{
		conn,
		messageBuffer,
	}
	log.Debugf("bind success for '%s': %d", peerId, channelId)

	bindSuccessChan <- conn
}

func (c *Client) writeTo(channelID uint16, payload []byte) (int, error) {
	msg := messages.MarshalTransportMsg(channelID, payload)
	n, err := c.relayConn.Write(msg)
	if err != nil {
		log.Errorf("failed to write transport message: %s", err)
	}
	return n, err
}

func (c *Client) generateConnReaderFN(messageBufferChan chan bufMsg) func(b []byte) (n int, err error) {
	return func(b []byte) (n int, err error) {
		select {
		case bufMsg, ok := <-messageBufferChan:
			if !ok {
				return 0, io.EOF
			}

			payload, err := messages.UnmarshalTransportPayload(bufMsg.buf)
			if err != nil {
				return 0, err
			}

			n = copy(b, payload)
			c.freeBuf(bufMsg.bufPtr)
		}
		return n, nil
	}
}

func (c *Client) freeBuf(ptr *[]byte) {
	c.msgPool.Put(ptr)
}
