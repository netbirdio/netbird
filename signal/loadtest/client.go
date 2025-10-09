package loadtest

import (
	"context"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"github.com/netbirdio/netbird/shared/signal/proto"
)

// Client represents a signal client for load testing
type Client struct {
	id         string
	conn       *grpc.ClientConn
	client     proto.SignalExchangeClient
	stream     proto.SignalExchange_ConnectStreamClient
	ctx        context.Context
	cancel     context.CancelFunc
	msgChannel chan *proto.EncryptedMessage
}

// NewClient creates a new signal client for load testing
func NewClient(serverURL, peerID string) (*Client, error) {
	addr, opts, err := parseServerURL(serverURL)
	if err != nil {
		return nil, fmt.Errorf("parse server URL: %w", err)
	}

	conn, err := grpc.Dial(addr, opts...)
	if err != nil {
		return nil, fmt.Errorf("dial server: %w", err)
	}

	client := proto.NewSignalExchangeClient(conn)
	ctx, cancel := context.WithCancel(context.Background())

	return &Client{
		id:         peerID,
		conn:       conn,
		client:     client,
		ctx:        ctx,
		cancel:     cancel,
		msgChannel: make(chan *proto.EncryptedMessage, 10),
	}, nil
}

// Connect establishes a stream connection to the signal server
func (c *Client) Connect() error {
	md := metadata.New(map[string]string{proto.HeaderId: c.id})
	ctx := metadata.NewOutgoingContext(c.ctx, md)

	stream, err := c.client.ConnectStream(ctx)
	if err != nil {
		return fmt.Errorf("connect stream: %w", err)
	}

	if _, err := stream.Header(); err != nil {
		return fmt.Errorf("receive header: %w", err)
	}

	c.stream = stream

	go c.receiveMessages()

	return nil
}

// SendMessage sends an encrypted message to a remote peer using the Send RPC
func (c *Client) SendMessage(remotePeerID string, body []byte) error {
	msg := &proto.EncryptedMessage{
		Key:       c.id,
		RemoteKey: remotePeerID,
		Body:      body,
	}

	ctx, cancel := context.WithTimeout(c.ctx, 5*time.Second)
	defer cancel()

	_, err := c.client.Send(ctx, msg)
	if err != nil {
		return fmt.Errorf("send message: %w", err)
	}

	return nil
}

// ReceiveMessage waits for and returns the next message
func (c *Client) ReceiveMessage() (*proto.EncryptedMessage, error) {
	select {
	case msg := <-c.msgChannel:
		return msg, nil
	case <-c.ctx.Done():
		return nil, c.ctx.Err()
	}
}

// Close closes the client connection
func (c *Client) Close() error {
	c.cancel()
	close(c.msgChannel)
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *Client) receiveMessages() {
	for {
		msg, err := c.stream.Recv()
		if err != nil {
			return
		}

		select {
		case c.msgChannel <- msg:
		case <-c.ctx.Done():
			return
		}
	}
}

func parseServerURL(serverURL string) (string, []grpc.DialOption, error) {
	serverURL = strings.TrimSpace(serverURL)
	if serverURL == "" {
		return "", nil, fmt.Errorf("server URL is empty")
	}

	var addr string
	var opts []grpc.DialOption

	if strings.HasPrefix(serverURL, "https://") {
		addr = strings.TrimPrefix(serverURL, "https://")
		return "", nil, fmt.Errorf("TLS support not yet implemented")
	} else if strings.HasPrefix(serverURL, "http://") {
		addr = strings.TrimPrefix(serverURL, "http://")
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		addr = serverURL
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	if !strings.Contains(addr, ":") {
		return "", nil, fmt.Errorf("server URL must include port")
	}

	return addr, opts, nil
}
