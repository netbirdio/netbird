package grpc

import (
	"context"
	"crypto/subtle"
	"fmt"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/management/server/activity"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/accesslogs"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

type reverseProxyStore interface {
	GetReverseProxies(ctx context.Context, lockStrength store.LockingStrength) ([]*reverseproxy.ReverseProxy, error)
	GetAccountReverseProxies(ctx context.Context, lockStrength store.LockingStrength, accountID string) ([]*reverseproxy.ReverseProxy, error)
	GetReverseProxyByID(ctx context.Context, lockStrength store.LockingStrength, accountID string, serviceID string) (*reverseproxy.ReverseProxy, error)
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

	// Manager for access logs
	accessLogManager accesslogs.Manager
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
func NewProxyServiceServer(store reverseProxyStore, keys keyStore, accessLogMgr accesslogs.Manager) *ProxyServiceServer {
	return &ProxyServiceServer{
		updatesChan:       make(chan *proto.ProxyMapping, 100),
		reverseProxyStore: store,
		keyStore:          keys,
		accessLogManager:  accessLogMgr,
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

		group, err := s.keyStore.GetGroupByName(ctx, rp.Name, rp.AccountID)
		if err != nil {
			log.WithFields(log.Fields{
				"proxy":   rp.Name,
				"account": rp.AccountID,
			}).WithError(err).Error("Failed to get group by name")
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
			log.WithFields(log.Fields{
				"proxy":   rp.Name,
				"account": rp.AccountID,
				"group":   group.ID,
			}).WithError(err).Error("Failed to create setup key")
			continue
		}

		if err := conn.stream.Send(&proto.GetMappingUpdateResponse{
			Mapping: []*proto.ProxyMapping{
				rp.ToProtoMapping(
					reverseproxy.Create, // Initial snapshot, all records are "new" for the proxy.
					key.Key,
				),
			},
		}); err != nil {
			log.WithError(err).Error("Failed to send proxy mapping")
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
	accessLog := req.GetLog()

	log.WithFields(log.Fields{
		"reverse_proxy_id": accessLog.GetServiceId(),
		"account_id":       accessLog.GetAccountId(),
		"host":             accessLog.GetHost(),
		"path":             accessLog.GetPath(),
		"method":           accessLog.GetMethod(),
		"response_code":    accessLog.GetResponseCode(),
		"duration_ms":      accessLog.GetDurationMs(),
		"source_ip":        accessLog.GetSourceIp(),
		"auth_mechanism":   accessLog.GetAuthMechanism(),
		"user_id":          accessLog.GetUserId(),
		"auth_success":     accessLog.GetAuthSuccess(),
	}).Debug("Access log from proxy")

	logEntry := &accesslogs.AccessLogEntry{}
	logEntry.FromProto(accessLog)

	if err := s.accessLogManager.SaveAccessLog(ctx, logEntry); err != nil {
		log.WithContext(ctx).Errorf("failed to save access log: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to save access log: %v", err)
	}

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

func (s *ProxyServiceServer) Authenticate(ctx context.Context, req *proto.AuthenticateRequest) (*proto.AuthenticateResponse, error) {
	proxy, err := s.reverseProxyStore.GetReverseProxyByID(ctx, store.LockingStrengthNone, req.GetAccountId(), req.GetId())
	if err != nil {
		// TODO: log the error
		return nil, status.Errorf(codes.FailedPrecondition, "failed to get reverse proxy from store: %v", err)
	}
	var authenticated bool
	switch v := req.GetRequest().(type) {
	case *proto.AuthenticateRequest_Pin:
		auth := proxy.Auth.PinAuth
		if auth == nil || !auth.Enabled {
			// TODO: log
			// Break here and use the default authenticated == false.
			break
		}
		authenticated = subtle.ConstantTimeCompare([]byte(auth.Pin), []byte(v.Pin.GetPin())) == 1
	case *proto.AuthenticateRequest_Password:
		auth := proxy.Auth.PasswordAuth
		if auth == nil || !auth.Enabled {
			// TODO: log
			// Break here and use the default authenticated == false.
			break
		}
		authenticated = subtle.ConstantTimeCompare([]byte(auth.Password), []byte(v.Password.GetPassword())) == 1
	}
	return &proto.AuthenticateResponse{
		Success: authenticated,
	}, nil
}
