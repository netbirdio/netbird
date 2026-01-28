package grpc

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/netbirdio/netbird/management/server/activity"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

type reverseProxyStore interface {
	GetReverseProxies(ctx context.Context, lockStrength store.LockingStrength) ([]*reverseproxy.ReverseProxy, error)
	GetAccountReverseProxies(ctx context.Context, lockStrength store.LockingStrength, accountID string) ([]*reverseproxy.ReverseProxy, error)
}

type keyStore interface {
	GetGroupByName(ctx context.Context, groupName string, accountID string) (*types.Group, error)
	CreateSetupKey(ctx context.Context, accountID string, keyName string, keyType types.SetupKeyType, expiresIn time.Duration, autoGroups []string, usageLimit int, userID string, ephemeral bool, allowExtraDNSLabels bool) (*types.SetupKey, error)
}

// ProxyServiceServer implements the ProxyService gRPC server
type ProxyServiceServer struct {
	proto.UnimplementedProxyServiceServer

	// Map of connected proxies: proxy_id -> proxy connection
	connectedProxies sync.Map

	// Channel for broadcasting reverse proxy updates to all proxies
	updatesChan chan *proto.ProxyMapping

	// Store of reverse proxies
	reverseProxyStore reverseProxyStore

	// Store for client setup keys
	keyStore keyStore
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
func NewProxyServiceServer(store reverseProxyStore, keys keyStore) *ProxyServiceServer {
	return &ProxyServiceServer{
		updatesChan:       make(chan *proto.ProxyMapping, 100),
		reverseProxyStore: store,
		keyStore:          keys,
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

// sendSnapshot sends the initial snapshot of all reverse proxies to proxy
func (s *ProxyServiceServer) sendSnapshot(ctx context.Context, conn *proxyConnection) error {
	reverseProxies, err := s.reverseProxyStore.GetReverseProxies(ctx, store.LockingStrengthNone) // TODO: check locking strength.
	if err != nil {
		// TODO: something?
		return fmt.Errorf("get account reverse proxies from store: %w", err)
	}

	for _, rp := range reverseProxies {
		if !rp.Enabled {
			// We don't care about disabled reverse proxies for snapshots.
			continue
		}

		// Fill auth values.
		// TODO: This will be removed soon as the management server should be handling authentication rather than the proxy, so probably not much use in fleshing this out too much.
		auth := &proto.Authentication{}
		if rp.Auth.BearerAuth != nil && rp.Auth.BearerAuth.Enabled {
			auth.Oidc = &proto.OIDC{
				Enabled: true,
				// TODO: fill other OIDC fields from account OIDC settings.
			}
		}
		if rp.Auth.PasswordAuth != nil && rp.Auth.PasswordAuth.Password != "" {
			auth.Password = &proto.Password{
				Enabled:  true,
				Password: rp.Auth.PasswordAuth.Password,
			}
		}
		if rp.Auth.PinAuth != nil && rp.Auth.PinAuth.Pin != "" {
			auth.Pin = &proto.Pin{
				Enabled: true,
				Pin:     rp.Auth.PinAuth.Pin,
			}
		}

		var paths []*proto.PathMapping
		for _, t := range rp.Targets {
			if !t.Enabled {
				// We don't care about disabled reverse proxy targets for snapshots.
				continue
			}
			// todo: review this fix
			path := "/"
			if t.Path != nil {
				path = "/"
			}

			paths = append(paths, &proto.PathMapping{
				Path:   path,
				Target: t.Host,
			})
		}

		group, err := s.keyStore.GetGroupByName(ctx, rp.Name, rp.AccountID)
		if err != nil {
			// TODO: log this?
			continue
		}

		// TODO: should this even be here? We're running in a loop, and on each proxy, this will create a LOT of setup key entries that we currently have no way to remove.
		key, err := s.keyStore.CreateSetupKey(ctx,
			rp.AccountID,
			rp.Name,
			types.SetupKeyReusable,
			0,
			[]string{group.ID},
			0,
			activity.SystemInitiator,
			true,
			false,
		)
		if err != nil {
			// TODO: how to handle this?
			continue
		}

		if err := conn.stream.Send(&proto.GetMappingUpdateResponse{
			Mapping: []*proto.ProxyMapping{
				{
					Type:     proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED, // Initial snapshot, all records are "new" for the proxy.
					Id:       rp.ID,
					Domain:   rp.Domain,
					Path:     paths,
					SetupKey: key.Key,
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
		"proxy_id":         "", // TODO: get proxy id, probably from context or maybe from request message.
		"reverse_proxy_id": req.GetLog().GetServiceId(),
		"host":             req.GetLog().GetHost(),
		"path":             req.GetLog().GetPath(),
		"method":           req.GetLog().GetMethod(),
		"response_code":    req.GetLog().GetResponseCode(),
		"duration_ms":      req.GetLog().GetDurationMs(),
		"source_ip":        req.GetLog().GetSourceIp(),
		"auth_mechanism":   req.GetLog().GetAuthMechanism(),
		"user_id":          req.GetLog().GetUserId(),
		"auth_success":     req.GetLog().GetAuthSuccess(),
	}).Info("Access log from proxy")

	// TODO: Store access log in database/metrics system
	return &proto.SendAccessLogResponse{}, nil
}

// SendReverseProxyUpdate broadcasts a reverse proxy update to all connected proxies.
// Management should call this when reverse proxies are created/updated/removed
func (s *ProxyServiceServer) SendReverseProxyUpdate(update *proto.ProxyMapping) {
	// Send it to all connected proxies
	log.Debugf("Broadcasting reverse proxy update to all connected proxies")
	s.connectedProxies.Range(func(key, value interface{}) bool {
		conn := value.(*proxyConnection)
		select {
		case conn.sendChan <- update:
			log.Debugf("Sent reverse proxy update with id %s to proxy %s", update.Id, conn.proxyID)
		default:
			log.Warnf("Failed to send reverse proxy update to proxy %s (channel full)", conn.proxyID)
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
