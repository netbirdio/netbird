package grpc

import (
	"context"
	"io"
	"sync"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/netbirdio/netbird/shared/management/proto"
)

// ProxyServiceServer implements the ProxyService gRPC server
type ProxyServiceServer struct {
	proto.UnimplementedProxyServiceServer

	// Map of connected proxies: proxy_id -> proxy connection
	connectedProxies sync.Map

	// Channel for broadcasting service updates to all proxies
	updatesChan chan *proto.ServiceUpdate
}

// proxyConnection represents a connected proxy
type proxyConnection struct {
	proxyID  string
	stream   proto.ProxyService_StreamServer
	sendChan chan *proto.ManagementMessage
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.RWMutex
}

// NewProxyServiceServer creates a new proxy service server
func NewProxyServiceServer() *ProxyServiceServer {
	return &ProxyServiceServer{
		updatesChan: make(chan *proto.ServiceUpdate, 100),
	}
}

// Stream handles the bidirectional stream with proxy clients
func (s *ProxyServiceServer) Stream(stream proto.ProxyService_StreamServer) error {
	ctx := stream.Context()

	peerInfo := ""
	if p, ok := peer.FromContext(ctx); ok {
		peerInfo = p.Addr.String()
	}

	log.Infof("New proxy connection from %s", peerInfo)

	firstMsg, err := stream.Recv()
	if err != nil {
		log.Errorf("Failed to receive ProxyHello: %v", err)
		return status.Errorf(codes.InvalidArgument, "expected ProxyHello message")
	}

	hello := firstMsg.GetHello()
	if hello == nil {
		log.Error("First message is not ProxyHello")
		return status.Errorf(codes.InvalidArgument, "first message must be ProxyHello")
	}

	proxyID := hello.GetProxyId()
	if proxyID == "" {
		return status.Errorf(codes.InvalidArgument, "proxy_id is required")
	}

	log.Infof("Proxy %s connected (version: %s, started: %s)",
		proxyID, hello.GetVersion(), hello.GetStartedAt().AsTime())

	connCtx, cancel := context.WithCancel(ctx)
	conn := &proxyConnection{
		proxyID:  proxyID,
		stream:   stream,
		sendChan: make(chan *proto.ManagementMessage, 100),
		ctx:      connCtx,
		cancel:   cancel,
	}

	s.connectedProxies.Store(proxyID, conn)
	defer func() {
		s.connectedProxies.Delete(proxyID)
		cancel()
		log.Infof("Proxy %s disconnected", proxyID)
	}()

	if err := s.sendSnapshot(conn); err != nil {
		log.Errorf("Failed to send snapshot to proxy %s: %v", proxyID, err)
		return err
	}

	errChan := make(chan error, 2)
	go s.sender(conn, errChan)

	go s.receiver(conn, errChan)

	select {
	case err := <-errChan:
		return err
	case <-connCtx.Done():
		return connCtx.Err()
	}
}

// sendSnapshot sends initial snapshot of all services to proxy
func (s *ProxyServiceServer) sendSnapshot(conn *proxyConnection) error {
	// TODO: Get actual services from database/store
	// For now, sending test service
	testService := &proto.ExposedServiceConfig{
		Id:     "test",
		Domain: "test.netbird.io",
		PathMappings: map[string]string{
			"/": "100.116.118.156:8181",
		},
		SetupKey: "some-key",
		Auth: &proto.AuthConfig{
			AuthType: &proto.AuthConfig_BearerAuth{
				BearerAuth: &proto.BearerAuthConfig{
					Enabled: true,
				},
			},
		},
	}

	snapshot := &proto.ServicesSnapshot{
		Services:  []*proto.ExposedServiceConfig{testService},
		Timestamp: timestamppb.Now(),
	}

	msg := &proto.ManagementMessage{
		Payload: &proto.ManagementMessage_Snapshot{
			Snapshot: snapshot,
		},
	}

	log.Infof("Sending snapshot to proxy %s with %d services", conn.proxyID, len(snapshot.Services))

	if err := conn.stream.Send(msg); err != nil {
		return status.Errorf(codes.Internal, "failed to send snapshot: %v", err)
	}

	return nil
}

// sender handles sending messages to proxy
func (s *ProxyServiceServer) sender(conn *proxyConnection, errChan chan<- error) {
	for {
		select {
		case msg := <-conn.sendChan:
			if err := conn.stream.Send(msg); err != nil {
				log.Errorf("Failed to send message to proxy %s: %v", conn.proxyID, err)
				errChan <- err
				return
			}
		case <-conn.ctx.Done():
			return
		}
	}
}

// receiver handles receiving messages from proxy
func (s *ProxyServiceServer) receiver(conn *proxyConnection, errChan chan<- error) {
	for {
		msg, err := conn.stream.Recv()
		if err == io.EOF {
			log.Infof("Proxy %s closed connection", conn.proxyID)
			errChan <- nil
			return
		}
		if err != nil {
			log.Errorf("Failed to receive from proxy %s: %v", conn.proxyID, err)
			errChan <- err
			return
		}

		// Handle different message types
		switch payload := msg.GetPayload().(type) {
		case *proto.ProxyMessage_RequestData:
			s.handleAccessLog(conn.proxyID, payload.RequestData)
		case *proto.ProxyMessage_Hello:
			log.Warnf("Received unexpected ProxyHello from %s after initial handshake", conn.proxyID)
		default:
			log.Warnf("Received unknown message type from proxy %s", conn.proxyID)
		}
	}
}

// handleAccessLog processes access log from proxy
func (s *ProxyServiceServer) handleAccessLog(proxyID string, data *proto.ProxyRequestData) {
	log.WithFields(log.Fields{
		"proxy_id":       proxyID,
		"service_id":     data.GetServiceId(),
		"host":           data.GetHost(),
		"path":           data.GetPath(),
		"method":         data.GetMethod(),
		"response_code":  data.GetResponseCode(),
		"duration_ms":    data.GetDurationMs(),
		"source_ip":      data.GetSourceIp(),
		"auth_mechanism": data.GetAuthMechanism(),
		"user_id":        data.GetUserId(),
		"auth_success":   data.GetAuthSuccess(),
	}).Info("Access log from proxy")

	// TODO: Store access log in database/metrics system
}

// SendServiceUpdate broadcasts a service update to all connected proxies
// This should be called by management when services are created/updated/removed
func (s *ProxyServiceServer) SendServiceUpdate(update *proto.ServiceUpdate) {
	updateMsg := &proto.ManagementMessage{
		Payload: &proto.ManagementMessage_Update{
			Update: update,
		},
	}

	// Send to all connected proxies
	s.connectedProxies.Range(func(key, value interface{}) bool {
		conn := value.(*proxyConnection)
		select {
		case conn.sendChan <- updateMsg:
			log.Debugf("Sent service update to proxy %s", conn.proxyID)
		default:
			log.Warnf("Failed to send service update to proxy %s (channel full)", conn.proxyID)
		}
		return true
	})
}

// GetConnectedProxies returns list of connected proxy IDs
func (s *ProxyServiceServer) GetConnectedProxies() []string {
	var proxies []string
	s.connectedProxies.Range(func(key, value interface{}) bool {
		proxies = append(proxies, key.(string))
		return true
	})
	return proxies
}
