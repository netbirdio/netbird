package grpc

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/netbirdio/netbird/shared/management/proto"
)

const (
	reconnectInterval = 5 * time.Second
	proxyVersion      = "0.1.0"
)

// ServiceUpdateHandler is called when services are added/updated/removed
type ServiceUpdateHandler func(update *proto.ServiceUpdate) error

// Client manages the gRPC connection to management server
type Client struct {
	proxyID              string
	managementURL        string
	conn                 *grpc.ClientConn
	stream               proto.ProxyService_StreamClient
	serviceUpdateHandler ServiceUpdateHandler
	accessLogChan        chan *proto.ProxyRequestData
	ctx                  context.Context
	cancel               context.CancelFunc
	mu                   sync.RWMutex
	connected            bool
}

// ClientConfig holds client configuration
type ClientConfig struct {
	ProxyID              string
	ManagementURL        string
	ServiceUpdateHandler ServiceUpdateHandler
}

// NewClient creates a new gRPC client for proxy-management communication
func NewClient(config ClientConfig) *Client {
	ctx, cancel := context.WithCancel(context.Background())

	return &Client{
		proxyID:              config.ProxyID,
		managementURL:        config.ManagementURL,
		serviceUpdateHandler: config.ServiceUpdateHandler,
		accessLogChan:        make(chan *proto.ProxyRequestData, 1000),
		ctx:                  ctx,
		cancel:               cancel,
	}
}

// Start connects to management server and maintains connection
func (c *Client) Start() error {
	go c.connectionLoop()
	return nil
}

// Stop closes the connection
func (c *Client) Stop() error {
	c.cancel()
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.stream != nil {
		// Try to close stream gracefully
		_ = c.stream.CloseSend()
	}

	if c.conn != nil {
		return c.conn.Close()
	}

	return nil
}

// SendAccessLog queues an access log to be sent to management
func (c *Client) SendAccessLog(log *proto.ProxyRequestData) {
	select {
	case c.accessLogChan <- log:
	default:
		// Channel full, drop log
	}
}

// IsConnected returns whether client is connected to management
func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

// connectionLoop maintains connection to management server
func (c *Client) connectionLoop() {
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		log.Infof("Connecting to management server at %s", c.managementURL)

		if err := c.connect(); err != nil {
			log.Errorf("Failed to connect to management: %v", err)
			c.setConnected(false)

			select {
			case <-c.ctx.Done():
				return
			case <-time.After(reconnectInterval):
				continue
			}
		}

		// Handle connection
		if err := c.handleConnection(); err != nil {
			log.Errorf("Connection error: %v", err)
			c.setConnected(false)
		}

		// Reconnect after delay
		select {
		case <-c.ctx.Done():
			return
		case <-time.After(reconnectInterval):
		}
	}
}

// connect establishes connection to management server
func (c *Client) connect() error {
	// Strip scheme from URL if present (gRPC doesn't use http:// or https://)
	target := c.managementURL
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimPrefix(target, "https://")

	// Create gRPC connection
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()), // TODO: Add TLS
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                20 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	}

	conn, err := grpc.Dial(target, opts...)
	if err != nil {
		return fmt.Errorf("failed to dial: %w", err)
	}

	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()

	// Create stream
	client := proto.NewProxyServiceClient(conn)
	stream, err := client.Stream(c.ctx)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to create stream: %w", err)
	}

	c.mu.Lock()
	c.stream = stream
	c.mu.Unlock()

	// Send ProxyHello
	hello := &proto.ProxyMessage{
		Payload: &proto.ProxyMessage_Hello{
			Hello: &proto.ProxyHello{
				ProxyId:   c.proxyID,
				Version:   proxyVersion,
				StartedAt: timestamppb.Now(),
			},
		},
	}

	if err := stream.Send(hello); err != nil {
		conn.Close()
		return fmt.Errorf("failed to send hello: %w", err)
	}

	c.setConnected(true)
	log.Info("Successfully connected to management server")

	return nil
}

// handleConnection manages the active connection
func (c *Client) handleConnection() error {
	errChan := make(chan error, 2)

	// Start sender goroutine
	go c.sender(errChan)

	// Start receiver goroutine
	go c.receiver(errChan)

	// Wait for error
	return <-errChan
}

// sender sends messages to management
func (c *Client) sender(errChan chan<- error) {
	for {
		select {
		case <-c.ctx.Done():
			errChan <- c.ctx.Err()
			return

		case accessLog := <-c.accessLogChan:
			msg := &proto.ProxyMessage{
				Payload: &proto.ProxyMessage_RequestData{
					RequestData: accessLog,
				},
			}

			c.mu.RLock()
			stream := c.stream
			c.mu.RUnlock()

			if stream == nil {
				continue
			}

			if err := stream.Send(msg); err != nil {
				log.Errorf("Failed to send access log: %v", err)
				errChan <- err
				return
			}
		}
	}
}

// receiver receives messages from management
func (c *Client) receiver(errChan chan<- error) {
	for {
		c.mu.RLock()
		stream := c.stream
		c.mu.RUnlock()

		if stream == nil {
			errChan <- fmt.Errorf("stream is nil")
			return
		}

		msg, err := stream.Recv()
		if err == io.EOF {
			log.Info("Management server closed connection")
			errChan <- io.EOF
			return
		}
		if err != nil {
			log.Errorf("Failed to receive: %v", err)
			errChan <- err
			return
		}

		// Handle message
		switch payload := msg.GetPayload().(type) {
		case *proto.ManagementMessage_Snapshot:
			c.handleSnapshot(payload.Snapshot)
		case *proto.ManagementMessage_Update:
			c.handleServiceUpdate(payload.Update)
		default:
			log.Warnf("Received unknown message type")
		}
	}
}

// handleSnapshot processes initial services snapshot
func (c *Client) handleSnapshot(snapshot *proto.ServicesSnapshot) {
	log.Infof("Received services snapshot with %d services", len(snapshot.Services))

	if c.serviceUpdateHandler == nil {
		log.Warn("No service update handler configured")
		return
	}

	// Process each service as a CREATED update
	for _, service := range snapshot.Services {
		update := &proto.ServiceUpdate{
			Type:      proto.ServiceUpdate_CREATED,
			Service:   service,
			ServiceId: service.Id,
		}

		if err := c.serviceUpdateHandler(update); err != nil {
			log.Errorf("Failed to handle service %s: %v", service.Id, err)
		}
	}
}

// handleServiceUpdate processes incremental service update
func (c *Client) handleServiceUpdate(update *proto.ServiceUpdate) {
	log.Infof("Received service update: %s %s", update.Type, update.ServiceId)

	if c.serviceUpdateHandler == nil {
		log.Warn("No service update handler configured")
		return
	}

	if err := c.serviceUpdateHandler(update); err != nil {
		log.Errorf("Failed to handle service update: %v", err)
	}
}

// setConnected updates connected status
func (c *Client) setConnected(connected bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.connected = connected
}
