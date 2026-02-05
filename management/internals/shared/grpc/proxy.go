package grpc

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net"
	"net/url"
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

type reverseProxyManager interface {
	SetCertificateIssuedAt(ctx context.Context, accountID, reverseProxyID string) error
	SetStatus(ctx context.Context, accountID, reverseProxyID string, status reverseproxy.ProxyStatus) error
}

type keyStore interface {
	GetGroupByName(ctx context.Context, groupName string, accountID string) (*types.Group, error)
	CreateSetupKey(ctx context.Context, accountID string, keyName string, keyType types.SetupKeyType, expiresIn time.Duration, autoGroups []string, usageLimit int, userID string, ephemeral bool, allowExtraDNSLabels bool) (*types.SetupKey, error)
}

// ClusterInfo contains information about a proxy cluster.
type ClusterInfo struct {
	Address          string
	ConnectedProxies int
}

// ProxyServiceServer implements the ProxyService gRPC server
type ProxyServiceServer struct {
	proto.UnimplementedProxyServiceServer

	// Map of connected proxies: proxy_id -> proxy connection
	connectedProxies sync.Map

	// Map of cluster address -> set of proxy IDs
	clusterProxies sync.Map

	// Channel for broadcasting reverse proxy updates to all proxies
	updatesChan chan *proto.ProxyMapping

	// Store of reverse proxies
	reverseProxyStore reverseProxyStore

	// Store for client setup keys
	keyStore keyStore

	// Manager for access logs
	accessLogManager accesslogs.Manager

	// Manager for reverse proxy operations
	reverseProxyManager reverseProxyManager
}

// proxyConnection represents a connected proxy
type proxyConnection struct {
	proxyID  string
	address  string
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

func (s *ProxyServiceServer) SetProxyManager(manager reverseProxyManager) {
	s.reverseProxyManager = manager
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

	proxyAddress := req.GetAddress()
	log.WithFields(log.Fields{
		"proxy_id": proxyID,
		"address":  proxyAddress,
		"version":  req.GetVersion(),
		"started":  req.GetStartedAt().AsTime(),
	}).Info("Proxy connected")

	connCtx, cancel := context.WithCancel(ctx)
	conn := &proxyConnection{
		proxyID:  proxyID,
		address:  proxyAddress,
		stream:   stream,
		sendChan: make(chan *proto.ProxyMapping, 100),
		ctx:      connCtx,
		cancel:   cancel,
	}

	s.connectedProxies.Store(proxyID, conn)
	s.addToCluster(conn.address, proxyID)
	log.WithFields(log.Fields{
		"proxy_id":      proxyID,
		"address":       proxyAddress,
		"cluster_addr":  extractClusterAddr(proxyAddress),
		"total_proxies": len(s.GetConnectedProxies()),
	}).Info("Proxy registered in cluster")
	defer func() {
		s.connectedProxies.Delete(proxyID)
		s.removeFromCluster(conn.address, proxyID)
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

// sendSnapshot sends the initial snapshot of reverse proxies to the connecting proxy.
// Only reverse proxies matching the proxy's cluster address are sent.
func (s *ProxyServiceServer) sendSnapshot(ctx context.Context, conn *proxyConnection) error {
	reverseProxies, err := s.reverseProxyStore.GetReverseProxies(ctx, store.LockingStrengthNone)
	if err != nil {
		return fmt.Errorf("get reverse proxies from store: %w", err)
	}

	proxyClusterAddr := extractClusterAddr(conn.address)

	for _, rp := range reverseProxies {
		if !rp.Enabled {
			continue
		}

		if rp.ProxyCluster != "" && proxyClusterAddr != "" && rp.ProxyCluster != proxyClusterAddr {
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
					reverseproxy.Create,
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

// extractClusterAddr extracts the host from a proxy address URL.
func extractClusterAddr(addr string) string {
	if addr == "" {
		return ""
	}
	u, err := url.Parse(addr)
	if err != nil {
		return addr
	}
	host := u.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
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

// GetConnectedProxyURLs returns a deduplicated list of URLs from all connected proxies.
func (s *ProxyServiceServer) GetConnectedProxyURLs() []string {
	seenUrls := make(map[string]struct{})
	var urls []string
	var proxyCount int
	s.connectedProxies.Range(func(key, value interface{}) bool {
		proxyCount++
		conn := value.(*proxyConnection)
		log.WithFields(log.Fields{
			"proxy_id": conn.proxyID,
			"address":  conn.address,
		}).Debug("checking connected proxy for URL")
		if _, seen := seenUrls[conn.address]; conn.address != "" && !seen {
			seenUrls[conn.address] = struct{}{}
			urls = append(urls, conn.address)
		}
		return true
	})
	log.WithFields(log.Fields{
		"total_proxies":  proxyCount,
		"unique_urls":    len(urls),
		"connected_urls": urls,
	}).Debug("GetConnectedProxyURLs result")
	return urls
}

// addToCluster registers a proxy in a cluster.
func (s *ProxyServiceServer) addToCluster(clusterAddr, proxyID string) {
	if clusterAddr == "" {
		return
	}
	proxySet, _ := s.clusterProxies.LoadOrStore(clusterAddr, &sync.Map{})
	proxySet.(*sync.Map).Store(proxyID, struct{}{})
	log.Debugf("Added proxy %s to cluster %s", proxyID, clusterAddr)
}

// removeFromCluster removes a proxy from a cluster.
func (s *ProxyServiceServer) removeFromCluster(clusterAddr, proxyID string) {
	if clusterAddr == "" {
		return
	}
	if proxySet, ok := s.clusterProxies.Load(clusterAddr); ok {
		proxySet.(*sync.Map).Delete(proxyID)
		log.Debugf("Removed proxy %s from cluster %s", proxyID, clusterAddr)
	}
}

// SendReverseProxyUpdateToCluster sends a reverse proxy update to all proxies in a specific cluster.
// If clusterAddr is empty, broadcasts to all connected proxies (backward compatibility).
func (s *ProxyServiceServer) SendReverseProxyUpdateToCluster(update *proto.ProxyMapping, clusterAddr string) {
	if clusterAddr == "" {
		s.SendReverseProxyUpdate(update)
		return
	}

	proxySet, ok := s.clusterProxies.Load(clusterAddr)
	if !ok {
		log.Debugf("No proxies connected for cluster %s", clusterAddr)
		return
	}

	log.Debugf("Sending reverse proxy update to cluster %s", clusterAddr)
	proxySet.(*sync.Map).Range(func(key, _ interface{}) bool {
		proxyID := key.(string)
		if connVal, ok := s.connectedProxies.Load(proxyID); ok {
			conn := connVal.(*proxyConnection)
			select {
			case conn.sendChan <- update:
				log.Debugf("Sent reverse proxy update with id %s to proxy %s in cluster %s", update.Id, proxyID, clusterAddr)
			default:
				log.Warnf("Failed to send reverse proxy update to proxy %s in cluster %s (channel full)", proxyID, clusterAddr)
			}
		}
		return true
	})
}

// GetAvailableClusters returns information about all connected proxy clusters.
func (s *ProxyServiceServer) GetAvailableClusters() []ClusterInfo {
	clusterCounts := make(map[string]int)
	s.clusterProxies.Range(func(key, value interface{}) bool {
		clusterAddr := key.(string)
		proxySet := value.(*sync.Map)
		count := 0
		proxySet.Range(func(_, _ interface{}) bool {
			count++
			return true
		})
		if count > 0 {
			clusterCounts[clusterAddr] = count
		}
		return true
	})

	clusters := make([]ClusterInfo, 0, len(clusterCounts))
	for addr, count := range clusterCounts {
		clusters = append(clusters, ClusterInfo{
			Address:          addr,
			ConnectedProxies: count,
		})
	}
	return clusters
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

// SendStatusUpdate handles status updates from proxy clients
func (s *ProxyServiceServer) SendStatusUpdate(ctx context.Context, req *proto.SendStatusUpdateRequest) (*proto.SendStatusUpdateResponse, error) {
	accountID := req.GetAccountId()
	reverseProxyID := req.GetReverseProxyId()
	protoStatus := req.GetStatus()
	certificateIssued := req.GetCertificateIssued()

	log.WithFields(log.Fields{
		"reverse_proxy_id":   reverseProxyID,
		"account_id":         accountID,
		"status":             protoStatus,
		"certificate_issued": certificateIssued,
		"error_message":      req.GetErrorMessage(),
	}).Debug("Status update from proxy")

	if reverseProxyID == "" || accountID == "" {
		return nil, status.Errorf(codes.InvalidArgument, "reverse_proxy_id and account_id are required")
	}

	if certificateIssued {
		if err := s.reverseProxyManager.SetCertificateIssuedAt(ctx, accountID, reverseProxyID); err != nil {
			log.WithContext(ctx).WithError(err).Error("Failed to set certificate issued timestamp")
			return nil, status.Errorf(codes.Internal, "failed to update certificate timestamp: %v", err)
		}
		log.WithFields(log.Fields{
			"reverse_proxy_id": reverseProxyID,
			"account_id":       accountID,
		}).Info("Certificate issued timestamp updated")
	}

	internalStatus := protoStatusToInternal(protoStatus)

	if err := s.reverseProxyManager.SetStatus(ctx, accountID, reverseProxyID, internalStatus); err != nil {
		log.WithContext(ctx).WithError(err).Error("Failed to set proxy status")
		return nil, status.Errorf(codes.Internal, "failed to update proxy status: %v", err)
	}

	log.WithFields(log.Fields{
		"reverse_proxy_id": reverseProxyID,
		"account_id":       accountID,
		"status":           internalStatus,
	}).Info("Proxy status updated")

	return &proto.SendStatusUpdateResponse{}, nil
}

// protoStatusToInternal maps proto status to internal status
func protoStatusToInternal(protoStatus proto.ProxyStatus) reverseproxy.ProxyStatus {
	switch protoStatus {
	case proto.ProxyStatus_PROXY_STATUS_PENDING:
		return reverseproxy.StatusPending
	case proto.ProxyStatus_PROXY_STATUS_ACTIVE:
		return reverseproxy.StatusActive
	case proto.ProxyStatus_PROXY_STATUS_TUNNEL_NOT_CREATED:
		return reverseproxy.StatusTunnelNotCreated
	case proto.ProxyStatus_PROXY_STATUS_CERTIFICATE_PENDING:
		return reverseproxy.StatusCertificatePending
	case proto.ProxyStatus_PROXY_STATUS_CERTIFICATE_FAILED:
		return reverseproxy.StatusCertificateFailed
	case proto.ProxyStatus_PROXY_STATUS_ERROR:
		return reverseproxy.StatusError
	default:
		return reverseproxy.StatusError
	}
}
