package loadtest

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"github.com/netbirdio/netbird/shared/signal/proto"
)

// Client represents a signal client for load testing
type Client struct {
	id         string
	serverURL  string
	config     *ClientConfig
	conn       *grpc.ClientConn
	client     proto.SignalExchangeClient
	stream     proto.SignalExchange_ConnectStreamClient
	ctx        context.Context
	cancel     context.CancelFunc
	msgChannel chan *proto.EncryptedMessage

	mu              sync.RWMutex
	reconnectCount  int64
	connected       bool
	receiverStarted bool
}

// ClientConfig holds optional configuration for the client
type ClientConfig struct {
	InsecureSkipVerify bool
	EnableReconnect    bool
	MaxReconnectDelay  time.Duration
	InitialRetryDelay  time.Duration
}

// NewClient creates a new signal client for load testing
func NewClient(serverURL, peerID string) (*Client, error) {
	return NewClientWithConfig(serverURL, peerID, nil)
}

// NewClientWithConfig creates a new signal client with custom TLS configuration
func NewClientWithConfig(serverURL, peerID string, config *ClientConfig) (*Client, error) {
	if config == nil {
		config = &ClientConfig{}
	}

	// Set default reconnect delays if not specified
	if config.EnableReconnect {
		if config.InitialRetryDelay == 0 {
			config.InitialRetryDelay = 100 * time.Millisecond
		}
		if config.MaxReconnectDelay == 0 {
			config.MaxReconnectDelay = 30 * time.Second
		}
	}

	addr, opts, err := parseServerURL(serverURL, config.InsecureSkipVerify)
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
		serverURL:  serverURL,
		config:     config,
		conn:       conn,
		client:     client,
		ctx:        ctx,
		cancel:     cancel,
		msgChannel: make(chan *proto.EncryptedMessage, 10),
		connected:  false,
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

	c.mu.Lock()
	c.stream = stream
	c.connected = true
	if !c.receiverStarted {
		c.receiverStarted = true
		c.mu.Unlock()
		go c.receiveMessages()
	} else {
		c.mu.Unlock()
	}

	return nil
}

// reconnectStream reconnects the stream without starting a new receiver goroutine
func (c *Client) reconnectStream() error {
	if !c.config.EnableReconnect {
		return fmt.Errorf("reconnect disabled")
	}

	delay := c.config.InitialRetryDelay
	attempt := 0

	for {
		select {
		case <-c.ctx.Done():
			return c.ctx.Err()
		case <-time.After(delay):
			attempt++
			log.Debugf("Client %s reconnect attempt %d (delay: %v)", c.id, attempt, delay)

			md := metadata.New(map[string]string{proto.HeaderId: c.id})
			ctx := metadata.NewOutgoingContext(c.ctx, md)

			stream, err := c.client.ConnectStream(ctx)
			if err != nil {
				log.Debugf("Client %s reconnect attempt %d failed: %v", c.id, attempt, err)
				delay *= 2
				if delay > c.config.MaxReconnectDelay {
					delay = c.config.MaxReconnectDelay
				}
				continue
			}

			if _, err := stream.Header(); err != nil {
				log.Debugf("Client %s reconnect header failed: %v", c.id, err)
				delay *= 2
				if delay > c.config.MaxReconnectDelay {
					delay = c.config.MaxReconnectDelay
				}
				continue
			}

			c.mu.Lock()
			c.stream = stream
			c.connected = true
			c.reconnectCount++
			c.mu.Unlock()

			log.Debugf("Client %s reconnected successfully (attempt %d, total reconnects: %d)",
				c.id, attempt, c.reconnectCount)
			return nil
		}
	}
}

// SendMessage sends an encrypted message to a remote peer using the Send RPC
func (c *Client) SendMessage(remotePeerID string, body []byte) error {
	msg := &proto.EncryptedMessage{
		Key:       c.id,
		RemoteKey: remotePeerID,
		Body:      body,
	}

	ctx, cancel := context.WithTimeout(c.ctx, 10*time.Second)
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
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *Client) receiveMessages() {
	for {
		c.mu.RLock()
		stream := c.stream
		c.mu.RUnlock()

		if stream == nil {
			return
		}

		msg, err := stream.Recv()
		if err != nil {
			// Check if context is cancelled before attempting reconnection
			select {
			case <-c.ctx.Done():
				return
			default:
			}

			c.mu.Lock()
			c.connected = false
			c.mu.Unlock()

			log.Debugf("Client %s receive error: %v", c.id, err)

			// Attempt reconnection if enabled
			if c.config.EnableReconnect {
				if reconnectErr := c.reconnectStream(); reconnectErr != nil {
					log.Debugf("Client %s reconnection failed: %v", c.id, reconnectErr)
					return
				}
				// Successfully reconnected, continue receiving
				continue
			}

			// Reconnect disabled, exit
			return
		}

		select {
		case c.msgChannel <- msg:
		case <-c.ctx.Done():
			return
		}
	}
}

// IsConnected returns whether the client is currently connected
func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

// GetReconnectCount returns the number of reconnections
func (c *Client) GetReconnectCount() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.reconnectCount
}

func parseServerURL(serverURL string, insecureSkipVerify bool) (string, []grpc.DialOption, error) {
	serverURL = strings.TrimSpace(serverURL)
	if serverURL == "" {
		return "", nil, fmt.Errorf("server URL is empty")
	}

	var addr string
	var opts []grpc.DialOption

	if strings.HasPrefix(serverURL, "https://") {
		addr = strings.TrimPrefix(serverURL, "https://")
		tlsConfig := &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: insecureSkipVerify,
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
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
