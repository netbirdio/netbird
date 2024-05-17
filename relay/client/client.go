package client

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/relay/client/dialer/ws"
	"github.com/netbirdio/netbird/relay/messages"
)

const (
	bufferSize = 65535 // optimise the buffer size
)

type connContainer struct {
	conn     *Conn
	messages chan []byte
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
}

func NewClient(serverAddress, peerID string) *Client {
	return &Client{
		serverAddress:   serverAddress,
		peerID:          peerID,
		channelsPending: make(map[string]chan net.Conn),
		channels:        make(map[uint16]*connContainer),
		msgPool: sync.Pool{
			New: func() any {
				return make([]byte, bufferSize)
			},
		},
	}
}

func (c *Client) Connect() error {
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

	c.relayConnState = true
	go c.readLoop()
	return nil
}

func (c *Client) BindChannel(remotePeerID string) (net.Conn, error) {
	if c.relayConn == nil {
		return nil, fmt.Errorf("client not connected")
	}

	bindSuccessChan := make(chan net.Conn, 1)
	c.channelsPending[remotePeerID] = bindSuccessChan
	msg := messages.MarshalBindNewChannelMsg(remotePeerID)
	_, err := c.relayConn.Write(msg)
	if err != nil {
		log.Errorf("failed to write out bind message: %s", err)
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("bind timeout")
	case c := <-bindSuccessChan:
		return c, nil
	}
}

func (c *Client) Close() error {
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
	return nil
}

func (c *Client) readLoop() {
	log := log.WithField("client_id", c.peerID)
	var errExit error
	var n int
	for {
		buf := c.msgPool.Get().([]byte)
		n, errExit = c.relayConn.Read(buf)
		if errExit != nil {
			break
		}

		msgType, err := messages.DetermineServerMsgType(buf[:n])
		if err != nil {
			log.Errorf("failed to determine message type: %s", err)
			c.msgPool.Put(buf)
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
			c.msgPool.Put(buf)
			continue
		case messages.MsgTypeTransport:
			channelId, err := messages.UnmarshalTransportID(buf[:n])
			if err != nil {
				log.Errorf("failed to parse transport message: %v", err)
				c.msgPool.Put(buf)
				continue
			}
			c.handleTransport(channelId, buf[:n])
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

	messageBuffer := make(chan []byte, 10)
	conn := NewConn(c, channelId, c.generateConnReaderFN(messageBuffer))

	c.channels[channelId] = &connContainer{
		conn,
		messageBuffer,
	}
	log.Debugf("bind success for '%s': %d", peerId, channelId)

	bindSuccessChan <- conn
}

func (c *Client) handleTransport(channelId uint16, msg []byte) {
	container, ok := c.channels[channelId]
	if !ok {
		log.Errorf("unexpected transport message for channel: %d", channelId)
		return
	}

	select {
	case container.messages <- msg:
	default:
		log.Errorf("dropping message for channel: %d", channelId)
	}
}

func (c *Client) writeTo(channelID uint16, payload []byte) (int, error) {
	msg := messages.MarshalTransportMsg(channelID, payload)
	n, err := c.relayConn.Write(msg)
	if err != nil {
		log.Errorf("failed to write transport message: %s", err)
	}
	return n, err
}

func (c *Client) generateConnReaderFN(messageBufferChan chan []byte) func(b []byte) (n int, err error) {
	return func(b []byte) (n int, err error) {
		defer c.msgPool.Put(b)
		select {
		case msg, ok := <-messageBufferChan:
			if !ok {
				return 0, io.EOF
			}

			payload, err := messages.UnmarshalTransportPayload(msg)
			if err != nil {
				return 0, err
			}

			n = copy(b, payload)
		}
		return n, nil
	}
}
