package grpc

import (
	"context"
	"fmt"
	"sync"

	"github.com/netbirdio/netbird/management/internals/modules/services"
	"github.com/netbirdio/netbird/management/server/store"
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

	if err := s.sendSnapshot(ctx, conn); err != nil {
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

type serviceStore interface {
	GetAccountServices(ctx context.Context, lockStrength store.LockingStrength, accountID string) ([]*services.Service, error)
}

// stubstore implements a serviceStore using stubbed out data rather than a real database connection.
type stubstore struct{}

func (stubstore) GetAccountServices(_ context.Context, _ store.LockingStrength, _ string) ([]*services.Service, error) {
	return []*services.Service{
		{
			ID:     "test",
			Domain: "test.netbird.io",
			Targets: []services.Target{
				{
					Enabled: true,
					Path:    "/",
					Host:    "100.116.118.156:8181",
				},
			},
			Enabled:           true,
			Exposed:           true,
			AuthBearerEnabled: true,
		},
	}, nil
}

// sendSnapshot sends the initial snapshot of all services to proxy
func (s *ProxyServiceServer) sendSnapshot(ctx context.Context, conn *proxyConnection) error {
	svcs, err := stubstore{}.GetAccountServices(ctx, store.LockingStrengthNone, conn.proxyID) // TODO: check locking strength and accountID. Use an actual database connection here!
	if err != nil {
		// TODO: something
		return fmt.Errorf("get account services from store: %w", err)
	}

	for _, svc := range svcs {
		if !svc.Enabled || !svc.Exposed {
			// We don't care about disabled services for snapshots.
			continue
		}

		// Fill auth values.
		// TODO: This will be removed soon as the management server should be handling authentication rather than the proxy, so probably not much use in fleshing this out too much.
		auth := &proto.Authentication{}
		if svc.AuthBearerEnabled {
			auth.Oidc = &proto.OIDC{
				Enabled: true,
				// TODO: fill other OIDC fields from account OIDC settings.
			}
		}
		if svc.AuthBasicPassword != "" {
			auth.Basic = &proto.HTTPBasic{
				Enabled:  true,
				Username: svc.AuthBasicUsername,
				Password: svc.AuthBasicPassword,
			}
		}
		if svc.AuthPINValue != "" {
			auth.Pin = &proto.Pin{
				Enabled: true,
				Pin:     svc.AuthPINValue,
			}
		}

		var paths []*proto.PathMapping
		for _, t := range svc.Targets {
			if !t.Enabled {
				// We don't care about disabled service targets for snapshots.
				continue
			}
			paths = append(paths, &proto.PathMapping{
				Path:   t.Path,
				Target: t.Host,
			})
		}

		if err := conn.stream.Send(&proto.GetMappingUpdateResponse{
			Mapping: []*proto.ProxyMapping{
				{
					Type:     proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED, // Initial snapshot, all records are "new" for the proxy.
					Id:       svc.ID,
					Domain:   svc.Domain,
					Path:     paths,
					SetupKey: "", // TODO: get the setup key.
					Auth:     auth,
				},
			},
		}); err != nil {
			// TODO: log the error, maybe retry?
			continue
		}
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
