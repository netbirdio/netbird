package grpc

import (
	"context"
	"sync"

	"github.com/netbirdio/netbird/shared/management/proto"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// ProxyServiceServer implements the ProxyService gRPC server
type ProxyServiceServer struct {
	proto.UnimplementedProxyServiceServer

	// Map of connected proxies: proxy_id -> proxy connection
	connectedProxies sync.Map

	// Channel for broadcasting service updates to all proxies
	updatesChan chan *proto.ProxyMapping
}

// proxyConnection represents a connected proxy
type proxyConnection struct {
	proxyID  string
	stream   proto.ProxyService_GetMappingUpdateServer
	sendChan chan *proto.ProxyMapping
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.RWMutex
}

// NewProxyServiceServer creates a new proxy service server
func NewProxyServiceServer() *ProxyServiceServer {
	return &ProxyServiceServer{
		updatesChan: make(chan *proto.ProxyMapping, 100),
	}
}

// GetMappingUpdate handles the control stream with proxy clients
func (s *ProxyServiceServer) GetMappingUpdate(req *proto.GetMappingUpdateRequest, stream proto.ProxyService_GetMappingUpdateServer) error {
	ctx := stream.Context()

	peerInfo := ""
	if p, ok := peer.FromContext(ctx); ok {
		peerInfo = p.Addr.String()
	}

	log.Infof("New proxy connection from %s", peerInfo)

	proxyID := req.GetProxyId()
	if proxyID == "" {
		return status.Errorf(codes.InvalidArgument, "proxy_id is required")
	}

	log.Infof("Proxy %s connected (version: %s, started: %s)",
		proxyID, req.GetVersion(), req.GetStartedAt().AsTime())

	connCtx, cancel := context.WithCancel(ctx)
	conn := &proxyConnection{
		proxyID:  proxyID,
		stream:   stream,
		sendChan: make(chan *proto.ProxyMapping, 100),
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

	select {
	case err := <-errChan:
		return err
	case <-connCtx.Done():
		return connCtx.Err()
	}
}

// sendSnapshot sends the initial snapshot of all services to proxy
func (s *ProxyServiceServer) sendSnapshot(conn *proxyConnection) error {
	// TODO: Get actual services from database/store
	// For now, sending test service
	testService := &proto.ProxyMapping{
		Id:     "test",
		Domain: "test.netbird.io",
		Path: []*proto.PathMapping{
			{
				Path:   "/",
				Target: "100.116.118.156:8181",
			},
		},
		SetupKey: "some-key",
		Auth: &proto.Authentication{
			Oidc: &proto.OIDC{
				Enabled: true,
			},
		},
	}

	snapshot := []*proto.ProxyMapping{
		testService,
	}

	msg := &proto.GetMappingUpdateResponse{
		Mapping: snapshot,
	}

	log.Infof("Sending snapshot to proxy %s with %d services", conn.proxyID, len(snapshot))

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
			if err := conn.stream.Send(&proto.GetMappingUpdateResponse{Mapping: []*proto.ProxyMapping{msg}}); err != nil {
				log.Errorf("Failed to send message to proxy %s: %v", conn.proxyID, err)
				errChan <- err
				return
			}
		case <-conn.ctx.Done():
			return
		}
	}
}

// SendAccessLog processes access log from proxy
func (s *ProxyServiceServer) SendAccessLog(ctx context.Context, req *proto.SendAccessLogRequest) (*proto.SendAccessLogResponse, error) {
	log.WithFields(log.Fields{
		"proxy_id":       "", // TODO: get proxy id, probably from context or maybe from request message.
		"service_id":     req.GetLog().GetServiceId(),
		"host":           req.GetLog().GetHost(),
		"path":           req.GetLog().GetPath(),
		"method":         req.GetLog().GetMethod(),
		"response_code":  req.GetLog().GetResponseCode(),
		"duration_ms":    req.GetLog().GetDurationMs(),
		"source_ip":      req.GetLog().GetSourceIp(),
		"auth_mechanism": req.GetLog().GetAuthMechanism(),
		"user_id":        req.GetLog().GetUserId(),
		"auth_success":   req.GetLog().GetAuthSuccess(),
	}).Info("Access log from proxy")

	// TODO: Store access log in database/metrics system
	return &proto.SendAccessLogResponse{}, nil
}

// SendServiceUpdate broadcasts a service update to all connected proxies.
// Management should call this when services are created/updated/removed
func (s *ProxyServiceServer) SendServiceUpdate(update *proto.ProxyMapping) {
	// Send it to all connected proxies
	s.connectedProxies.Range(func(key, value interface{}) bool {
		conn := value.(*proxyConnection)
		select {
		case conn.sendChan <- update:
			log.Debugf("Sent service update to proxy %s", conn.proxyID)
		default:
			log.Warnf("Failed to send service update to proxy %s (channel full)", conn.proxyID)
		}
		return true
	})
}

// GetConnectedProxies returns a list of connected proxy IDs
func (s *ProxyServiceServer) GetConnectedProxies() []string {
	var proxies []string
	s.connectedProxies.Range(func(key, value interface{}) bool {
		proxies = append(proxies, key.(string))
		return true
	})
	return proxies
}
