package grpc

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/shared/management/domain"

	"github.com/netbirdio/netbird/management/internals/modules/peers"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/accesslogs"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/sessionkey"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/management/server/users"
	proxyauth "github.com/netbirdio/netbird/proxy/auth"
	"github.com/netbirdio/netbird/shared/hash/argon2id"
	"github.com/netbirdio/netbird/shared/management/proto"
)

type ProxyOIDCConfig struct {
	Issuer      string
	ClientID    string
	Scopes      []string
	CallbackURL string
	HMACKey     []byte

	Audience     string
	KeysLocation string
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

	// Manager for access logs
	accessLogManager accesslogs.Manager

	// Manager for reverse proxy operations
	reverseProxyManager reverseproxy.Manager

	// Manager for peers
	peersManager peers.Manager

	// Manager for users
	usersManager users.Manager

	// Store for one-time authentication tokens
	tokenStore *OneTimeTokenStore

	// OIDC configuration for proxy authentication
	oidcConfig ProxyOIDCConfig

	// TODO: use database to store these instead?
	// pkceVerifiers stores PKCE code verifiers keyed by OAuth state.
	// Entries expire after pkceVerifierTTL to prevent unbounded growth.
	pkceVerifiers     sync.Map
	pkceCleanupCancel context.CancelFunc
}

const pkceVerifierTTL = 10 * time.Minute

type pkceEntry struct {
	verifier  string
	createdAt time.Time
}

// proxyConnection represents a connected proxy
type proxyConnection struct {
	proxyID  string
	address  string
	stream   proto.ProxyService_GetMappingUpdateServer
	sendChan chan *proto.ProxyMapping
	ctx      context.Context
	cancel   context.CancelFunc
}

// NewProxyServiceServer creates a new proxy service server.
func NewProxyServiceServer(accessLogMgr accesslogs.Manager, tokenStore *OneTimeTokenStore, oidcConfig ProxyOIDCConfig, peersManager peers.Manager, usersManager users.Manager) *ProxyServiceServer {
	ctx, cancel := context.WithCancel(context.Background())
	s := &ProxyServiceServer{
		updatesChan:       make(chan *proto.ProxyMapping, 100),
		accessLogManager:  accessLogMgr,
		oidcConfig:        oidcConfig,
		tokenStore:        tokenStore,
		peersManager:      peersManager,
		usersManager:      usersManager,
		pkceCleanupCancel: cancel,
	}
	go s.cleanupPKCEVerifiers(ctx)
	return s
}

// cleanupPKCEVerifiers periodically removes expired PKCE verifiers.
func (s *ProxyServiceServer) cleanupPKCEVerifiers(ctx context.Context) {
	ticker := time.NewTicker(pkceVerifierTTL)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			s.pkceVerifiers.Range(func(key, value any) bool {
				if entry, ok := value.(pkceEntry); ok && now.Sub(entry.createdAt) > pkceVerifierTTL {
					s.pkceVerifiers.Delete(key)
				}
				return true
			})
		}
	}
}

// Close stops background goroutines.
func (s *ProxyServiceServer) Close() {
	s.pkceCleanupCancel()
}

func (s *ProxyServiceServer) SetProxyManager(manager reverseproxy.Manager) {
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
	if !isProxyAddressValid(proxyAddress) {
		return status.Errorf(codes.InvalidArgument, "proxy address is invalid")
	}

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
		"cluster_addr":  proxyAddress,
		"total_proxies": len(s.GetConnectedProxies()),
	}).Info("Proxy registered in cluster")
	defer func() {
		s.connectedProxies.Delete(proxyID)
		s.removeFromCluster(conn.address, proxyID)
		cancel()
		log.Infof("Proxy %s disconnected", proxyID)
	}()

	if err := s.sendSnapshot(ctx, conn); err != nil {
		return fmt.Errorf("send snapshot to proxy %s: %w", proxyID, err)
	}

	errChan := make(chan error, 2)
	go s.sender(conn, errChan)

	select {
	case err := <-errChan:
		return fmt.Errorf("send update to proxy %s: %w", proxyID, err)
	case <-connCtx.Done():
		return connCtx.Err()
	}
}

// sendSnapshot sends the initial snapshot of services to the connecting proxy.
// Only services matching the proxy's cluster address are sent.
func (s *ProxyServiceServer) sendSnapshot(ctx context.Context, conn *proxyConnection) error {
	services, err := s.reverseProxyManager.GetGlobalServices(ctx)
	if err != nil {
		return fmt.Errorf("get services from store: %w", err)
	}

	if !isProxyAddressValid(conn.address) {
		return fmt.Errorf("proxy address is invalid")
	}

	var filtered []*reverseproxy.Service
	for _, service := range services {
		if !service.Enabled {
			continue
		}
		if service.ProxyCluster == "" || service.ProxyCluster != conn.address {
			continue
		}
		filtered = append(filtered, service)
	}

	if len(filtered) == 0 {
		if err := conn.stream.Send(&proto.GetMappingUpdateResponse{
			InitialSyncComplete: true,
		}); err != nil {
			return fmt.Errorf("send snapshot completion: %w", err)
		}
		return nil
	}

	for i, service := range filtered {
		// Generate one-time authentication token for each service in the snapshot
		// Tokens are not persistent on the proxy, so we need to generate new ones on reconnection
		token, err := s.tokenStore.GenerateToken(service.AccountID, service.ID, 5*time.Minute)
		if err != nil {
			log.WithFields(log.Fields{
				"service": service.Name,
				"account": service.AccountID,
			}).WithError(err).Error("failed to generate auth token for snapshot")
			continue
		}

		if err := conn.stream.Send(&proto.GetMappingUpdateResponse{
			Mapping: []*proto.ProxyMapping{
				service.ToProtoMapping(
					reverseproxy.Create, // Initial snapshot, all records are "new" for the proxy.
					token,
					s.GetOIDCValidationConfig(),
				),
			},
			InitialSyncComplete: i == len(filtered)-1,
		}); err != nil {
			log.WithFields(log.Fields{
				"domain":  service.Domain,
				"account": service.AccountID,
			}).WithError(err).Error("failed to send proxy mapping")
			return fmt.Errorf("send proxy mapping: %w", err)
		}
	}

	return nil
}

// isProxyAddressValid validates a proxy address
func isProxyAddressValid(addr string) bool {
	_, err := domain.ValidateDomains([]string{addr})
	return err == nil
}

// sender handles sending messages to proxy
func (s *ProxyServiceServer) sender(conn *proxyConnection, errChan chan<- error) {
	for {
		select {
		case msg := <-conn.sendChan:
			if err := conn.stream.Send(&proto.GetMappingUpdateResponse{Mapping: []*proto.ProxyMapping{msg}}); err != nil {
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

	fields := log.Fields{
		"service_id": accessLog.GetServiceId(),
		"account_id": accessLog.GetAccountId(),
		"host":       accessLog.GetHost(),
		"source_ip":  accessLog.GetSourceIp(),
	}
	if mechanism := accessLog.GetAuthMechanism(); mechanism != "" {
		fields["auth_mechanism"] = mechanism
	}
	if userID := accessLog.GetUserId(); userID != "" {
		fields["user_id"] = userID
	}
	if !accessLog.GetAuthSuccess() {
		fields["auth_success"] = false
	}
	log.WithFields(fields).Debugf("%s %s %d (%dms)",
		accessLog.GetMethod(),
		accessLog.GetPath(),
		accessLog.GetResponseCode(),
		accessLog.GetDurationMs(),
	)

	logEntry := &accesslogs.AccessLogEntry{}
	logEntry.FromProto(accessLog)

	if err := s.accessLogManager.SaveAccessLog(ctx, logEntry); err != nil {
		log.WithContext(ctx).Errorf("failed to save access log: %v", err)
		return nil, status.Errorf(codes.Internal, "save access log: %v", err)
	}

	return &proto.SendAccessLogResponse{}, nil
}

// SendServiceUpdate broadcasts a service update to all connected proxy servers.
// Management should call this when services are created/updated/removed.
// For create/update operations a unique one-time auth token is generated per
// proxy so that every replica can independently authenticate with management.
func (s *ProxyServiceServer) SendServiceUpdate(update *proto.ProxyMapping) {
	log.Debugf("Broadcasting service update to all connected proxy servers")
	s.connectedProxies.Range(func(key, value interface{}) bool {
		conn := value.(*proxyConnection)
		msg := s.perProxyMessage(update, conn.proxyID)
		if msg == nil {
			return true
		}
		select {
		case conn.sendChan <- msg:
			log.Debugf("Sent service update with id %s to proxy server %s", update.Id, conn.proxyID)
		default:
			log.Warnf("Failed to send service update to proxy server %s (channel full)", conn.proxyID)
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

// SendServiceUpdateToCluster sends a service update to all proxy servers in a specific cluster.
// If clusterAddr is empty, broadcasts to all connected proxy servers (backward compatibility).
// For create/update operations a unique one-time auth token is generated per
// proxy so that every replica can independently authenticate with management.
func (s *ProxyServiceServer) SendServiceUpdateToCluster(update *proto.ProxyMapping, clusterAddr string) {
	if clusterAddr == "" {
		s.SendServiceUpdate(update)
		return
	}

	proxySet, ok := s.clusterProxies.Load(clusterAddr)
	if !ok {
		log.Debugf("No proxies connected for cluster %s", clusterAddr)
		return
	}

	log.Debugf("Sending service update to cluster %s", clusterAddr)
	proxySet.(*sync.Map).Range(func(key, _ interface{}) bool {
		proxyID := key.(string)
		if connVal, ok := s.connectedProxies.Load(proxyID); ok {
			conn := connVal.(*proxyConnection)
			msg := s.perProxyMessage(update, proxyID)
			if msg == nil {
				return true
			}
			select {
			case conn.sendChan <- msg:
				log.Debugf("Sent service update with id %s to proxy %s in cluster %s", update.Id, proxyID, clusterAddr)
			default:
				log.Warnf("Failed to send service update to proxy %s in cluster %s (channel full)", proxyID, clusterAddr)
			}
		}
		return true
	})
}

// perProxyMessage returns a copy of update with a fresh one-time token for
// create/update operations. For delete operations the original message is
// returned unchanged because proxies do not need to authenticate for removal.
// Returns nil if token generation fails (the proxy should be skipped).
func (s *ProxyServiceServer) perProxyMessage(update *proto.ProxyMapping, proxyID string) *proto.ProxyMapping {
	if update.Type == proto.ProxyMappingUpdateType_UPDATE_TYPE_REMOVED || update.AccountId == "" {
		return update
	}

	token, err := s.tokenStore.GenerateToken(update.AccountId, update.Id, 5*time.Minute)
	if err != nil {
		log.Warnf("Failed to generate token for proxy %s: %v", proxyID, err)
		return nil
	}

	msg := shallowCloneMapping(update)
	msg.AuthToken = token
	return msg
}

// shallowCloneMapping creates a shallow copy of a ProxyMapping, reusing the
// same slice/pointer fields. Only scalar fields that differ per proxy (AuthToken)
// should be set on the copy.
func shallowCloneMapping(m *proto.ProxyMapping) *proto.ProxyMapping {
	return &proto.ProxyMapping{
		Type:             m.Type,
		Id:               m.Id,
		AccountId:        m.AccountId,
		Domain:           m.Domain,
		Path:             m.Path,
		Auth:             m.Auth,
		PassHostHeader:   m.PassHostHeader,
		RewriteRedirects: m.RewriteRedirects,
	}
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
	service, err := s.reverseProxyManager.GetServiceByID(ctx, req.GetAccountId(), req.GetId())
	if err != nil {
		log.WithContext(ctx).Debugf("failed to get service from store: %v", err)
		return nil, status.Errorf(codes.FailedPrecondition, "get service from store: %v", err)
	}

	authenticated, userId, method := s.authenticateRequest(ctx, req, service)

	token, err := s.generateSessionToken(ctx, authenticated, service, userId, method)
	if err != nil {
		return nil, err
	}

	return &proto.AuthenticateResponse{
		Success:      authenticated,
		SessionToken: token,
	}, nil
}

func (s *ProxyServiceServer) authenticateRequest(ctx context.Context, req *proto.AuthenticateRequest, service *reverseproxy.Service) (bool, string, proxyauth.Method) {
	switch v := req.GetRequest().(type) {
	case *proto.AuthenticateRequest_Pin:
		return s.authenticatePIN(ctx, req.GetId(), v, service.Auth.PinAuth)
	case *proto.AuthenticateRequest_Password:
		return s.authenticatePassword(ctx, req.GetId(), v, service.Auth.PasswordAuth)
	default:
		return false, "", ""
	}
}

func (s *ProxyServiceServer) authenticatePIN(ctx context.Context, serviceID string, req *proto.AuthenticateRequest_Pin, auth *reverseproxy.PINAuthConfig) (bool, string, proxyauth.Method) {
	if auth == nil || !auth.Enabled {
		log.WithContext(ctx).Debugf("PIN authentication attempted but not enabled for service %s", serviceID)
		return false, "", ""
	}

	if err := argon2id.Verify(req.Pin.GetPin(), auth.Pin); err != nil {
		s.logAuthenticationError(ctx, err, "PIN")
		return false, "", ""
	}

	return true, "pin-user", proxyauth.MethodPIN
}

func (s *ProxyServiceServer) authenticatePassword(ctx context.Context, serviceID string, req *proto.AuthenticateRequest_Password, auth *reverseproxy.PasswordAuthConfig) (bool, string, proxyauth.Method) {
	if auth == nil || !auth.Enabled {
		log.WithContext(ctx).Debugf("password authentication attempted but not enabled for service %s", serviceID)
		return false, "", ""
	}

	if err := argon2id.Verify(req.Password.GetPassword(), auth.Password); err != nil {
		s.logAuthenticationError(ctx, err, "Password")
		return false, "", ""
	}

	return true, "password-user", proxyauth.MethodPassword
}

func (s *ProxyServiceServer) logAuthenticationError(ctx context.Context, err error, authType string) {
	if errors.Is(err, argon2id.ErrMismatchedHashAndPassword) {
		log.WithContext(ctx).Tracef("%s authentication failed: invalid credentials", authType)
	} else {
		log.WithContext(ctx).Errorf("%s authentication error: %v", authType, err)
	}
}

func (s *ProxyServiceServer) generateSessionToken(ctx context.Context, authenticated bool, service *reverseproxy.Service, userId string, method proxyauth.Method) (string, error) {
	if !authenticated || service.SessionPrivateKey == "" {
		return "", nil
	}

	token, err := sessionkey.SignToken(
		service.SessionPrivateKey,
		userId,
		service.Domain,
		method,
		proxyauth.DefaultSessionExpiry,
	)
	if err != nil {
		log.WithContext(ctx).WithError(err).Error("failed to sign session token")
		return "", status.Errorf(codes.Internal, "sign session token: %v", err)
	}

	return token, nil
}

// SendStatusUpdate handles status updates from proxy clients
func (s *ProxyServiceServer) SendStatusUpdate(ctx context.Context, req *proto.SendStatusUpdateRequest) (*proto.SendStatusUpdateResponse, error) {
	accountID := req.GetAccountId()
	serviceID := req.GetServiceId()
	protoStatus := req.GetStatus()
	certificateIssued := req.GetCertificateIssued()

	log.WithFields(log.Fields{
		"service_id":         serviceID,
		"account_id":         accountID,
		"status":             protoStatus,
		"certificate_issued": certificateIssued,
		"error_message":      req.GetErrorMessage(),
	}).Debug("Status update from proxy server")

	if serviceID == "" || accountID == "" {
		return nil, status.Errorf(codes.InvalidArgument, "service_id and account_id are required")
	}

	if certificateIssued {
		if err := s.reverseProxyManager.SetCertificateIssuedAt(ctx, accountID, serviceID); err != nil {
			log.WithContext(ctx).WithError(err).Error("failed to set certificate issued timestamp")
			return nil, status.Errorf(codes.Internal, "update certificate timestamp: %v", err)
		}
		log.WithFields(log.Fields{
			"service_id": serviceID,
			"account_id": accountID,
		}).Info("Certificate issued timestamp updated")
	}

	internalStatus := protoStatusToInternal(protoStatus)

	if err := s.reverseProxyManager.SetStatus(ctx, accountID, serviceID, internalStatus); err != nil {
		log.WithContext(ctx).WithError(err).Error("failed to update service status")
		return nil, status.Errorf(codes.Internal, "update service status: %v", err)
	}

	log.WithFields(log.Fields{
		"service_id": serviceID,
		"account_id": accountID,
		"status":     internalStatus,
	}).Info("Service status updated")

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

// CreateProxyPeer handles proxy peer creation with one-time token authentication
func (s *ProxyServiceServer) CreateProxyPeer(ctx context.Context, req *proto.CreateProxyPeerRequest) (*proto.CreateProxyPeerResponse, error) {
	serviceID := req.GetServiceId()
	accountID := req.GetAccountId()
	token := req.GetToken()
	cluster := req.GetCluster()
	key := req.WireguardPublicKey

	log.WithFields(log.Fields{
		"service_id": serviceID,
		"account_id": accountID,
		"cluster":    cluster,
	}).Debug("CreateProxyPeer request received")

	if serviceID == "" || accountID == "" || token == "" {
		log.Warn("CreateProxyPeer: missing required fields")
		return &proto.CreateProxyPeerResponse{
			Success:      false,
			ErrorMessage: strPtr("missing required fields: service_id, account_id, and token are required"),
		}, nil
	}

	if err := s.tokenStore.ValidateAndConsume(token, accountID, serviceID); err != nil {
		log.WithFields(log.Fields{
			"service_id": serviceID,
			"account_id": accountID,
		}).WithError(err).Warn("CreateProxyPeer: token validation failed")
		return &proto.CreateProxyPeerResponse{
			Success:      false,
			ErrorMessage: strPtr("authentication failed: invalid or expired token"),
		}, status.Errorf(codes.Unauthenticated, "token validation: %v", err)
	}

	err := s.peersManager.CreateProxyPeer(ctx, accountID, key, cluster)
	if err != nil {
		log.WithFields(log.Fields{
			"service_id": serviceID,
			"account_id": accountID,
		}).WithError(err).Error("failed to create proxy peer")
		return &proto.CreateProxyPeerResponse{
			Success:      false,
			ErrorMessage: strPtr(fmt.Sprintf("create proxy peer: %v", err)),
		}, status.Errorf(codes.Internal, "create proxy peer: %v", err)
	}

	return &proto.CreateProxyPeerResponse{
		Success: true,
	}, nil
}

// strPtr is a helper to create a string pointer for optional proto fields
func strPtr(s string) *string {
	return &s
}

func (s *ProxyServiceServer) GetOIDCURL(ctx context.Context, req *proto.GetOIDCURLRequest) (*proto.GetOIDCURLResponse, error) {
	redirectURL, err := url.Parse(req.GetRedirectUrl())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "parse redirect url: %v", err)
	}
	// Validate redirectURL against known service endpoints to avoid abuse of OIDC redirection.
	services, err := s.reverseProxyManager.GetAccountServices(ctx, req.GetAccountId())
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get account services: %v", err)
		return nil, status.Errorf(codes.FailedPrecondition, "get account services: %v", err)
	}
	var found bool
	for _, service := range services {
		if service.Domain == redirectURL.Hostname() {
			found = true
			break
		}
	}
	if !found {
		log.WithContext(ctx).Debugf("OIDC redirect URL %q does not match any service domain", redirectURL.Hostname())
		return nil, status.Errorf(codes.FailedPrecondition, "service not found in store")
	}

	provider, err := oidc.NewProvider(ctx, s.oidcConfig.Issuer)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to create OIDC provider: %v", err)
		return nil, status.Errorf(codes.FailedPrecondition, "create OIDC provider: %v", err)
	}

	scopes := s.oidcConfig.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}

	// Generate a random nonce to ensure each OIDC request gets a unique state.
	// Without this, multiple requests to the same URL would generate the same state
	// but different PKCE verifiers, causing the later verifier to overwrite the earlier one.
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, status.Errorf(codes.Internal, "generate nonce: %v", err)
	}
	nonceB64 := base64.URLEncoding.EncodeToString(nonce)

	// Using an HMAC here to avoid redirection state being modified.
	// State format: base64(redirectURL)|nonce|hmac(redirectURL|nonce)
	payload := redirectURL.String() + "|" + nonceB64
	hmacSum := s.generateHMAC(payload)
	state := fmt.Sprintf("%s|%s|%s", base64.URLEncoding.EncodeToString([]byte(redirectURL.String())), nonceB64, hmacSum)

	codeVerifier := oauth2.GenerateVerifier()
	s.pkceVerifiers.Store(state, pkceEntry{verifier: codeVerifier, createdAt: time.Now()})

	return &proto.GetOIDCURLResponse{
		Url: (&oauth2.Config{
			ClientID:    s.oidcConfig.ClientID,
			Endpoint:    provider.Endpoint(),
			RedirectURL: s.oidcConfig.CallbackURL,
			Scopes:      scopes,
		}).AuthCodeURL(state, oauth2.S256ChallengeOption(codeVerifier)),
	}, nil
}

// GetOIDCConfig returns the OIDC configuration for token validation.
func (s *ProxyServiceServer) GetOIDCConfig() ProxyOIDCConfig {
	return s.oidcConfig
}

// GetOIDCValidationConfig returns the OIDC configuration for token validation
// in the format needed by ToProtoMapping.
func (s *ProxyServiceServer) GetOIDCValidationConfig() reverseproxy.OIDCValidationConfig {
	return reverseproxy.OIDCValidationConfig{
		Issuer:             s.oidcConfig.Issuer,
		Audiences:          []string{s.oidcConfig.Audience},
		KeysLocation:       s.oidcConfig.KeysLocation,
		MaxTokenAgeSeconds: 0, // No max token age by default
	}
}

func (s *ProxyServiceServer) generateHMAC(input string) string {
	mac := hmac.New(sha256.New, s.oidcConfig.HMACKey)
	mac.Write([]byte(input))
	return hex.EncodeToString(mac.Sum(nil))
}

// ValidateState validates the state parameter from an OAuth callback.
// Returns the original redirect URL if valid, or an error if invalid.
func (s *ProxyServiceServer) ValidateState(state string) (verifier, redirectURL string, err error) {
	v, ok := s.pkceVerifiers.LoadAndDelete(state)
	if !ok {
		return "", "", errors.New("no verifier for state")
	}
	entry, ok := v.(pkceEntry)
	if !ok {
		return "", "", errors.New("invalid verifier for state")
	}
	if time.Since(entry.createdAt) > pkceVerifierTTL {
		return "", "", errors.New("PKCE verifier expired")
	}
	verifier = entry.verifier

	// State format: base64(redirectURL)|nonce|hmac(redirectURL|nonce)
	parts := strings.Split(state, "|")
	if len(parts) != 3 {
		return "", "", errors.New("invalid state format")
	}

	encodedURL := parts[0]
	nonce := parts[1]
	providedHMAC := parts[2]

	redirectURLBytes, err := base64.URLEncoding.DecodeString(encodedURL)
	if err != nil {
		return "", "", fmt.Errorf("invalid state encoding: %w", err)
	}
	redirectURL = string(redirectURLBytes)

	payload := redirectURL + "|" + nonce
	expectedHMAC := s.generateHMAC(payload)

	if !hmac.Equal([]byte(providedHMAC), []byte(expectedHMAC)) {
		return "", "", errors.New("invalid state signature")
	}

	return verifier, redirectURL, nil
}

// GenerateSessionToken creates a signed session JWT for the given domain and user.
func (s *ProxyServiceServer) GenerateSessionToken(ctx context.Context, domain, userID string, method proxyauth.Method) (string, error) {
	// Find the service by domain to get its signing key
	services, err := s.reverseProxyManager.GetGlobalServices(ctx)
	if err != nil {
		return "", fmt.Errorf("get services: %w", err)
	}

	var service *reverseproxy.Service
	for _, svc := range services {
		if svc.Domain == domain {
			service = svc
			break
		}
	}
	if service == nil {
		return "", fmt.Errorf("service not found for domain: %s", domain)
	}

	if service.SessionPrivateKey == "" {
		return "", fmt.Errorf("no session key configured for domain: %s", domain)
	}

	return sessionkey.SignToken(
		service.SessionPrivateKey,
		userID,
		domain,
		method,
		proxyauth.DefaultSessionExpiry,
	)
}

// ValidateUserGroupAccess checks if a user has access to a service.
// It looks up the service within the user's account only, then optionally checks
// group membership if BearerAuth with DistributionGroups is configured.
func (s *ProxyServiceServer) ValidateUserGroupAccess(ctx context.Context, domain, userID string) error {
	user, err := s.usersManager.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found: %s", userID)
	}

	service, err := s.getAccountServiceByDomain(ctx, user.AccountID, domain)
	if err != nil {
		return err
	}

	if service.Auth.BearerAuth == nil || !service.Auth.BearerAuth.Enabled {
		return nil
	}

	allowedGroups := service.Auth.BearerAuth.DistributionGroups
	if len(allowedGroups) == 0 {
		return nil
	}

	allowedSet := make(map[string]bool, len(allowedGroups))
	for _, groupID := range allowedGroups {
		allowedSet[groupID] = true
	}

	for _, groupID := range user.AutoGroups {
		if allowedSet[groupID] {
			log.WithFields(log.Fields{
				"user_id":  user.Id,
				"group_id": groupID,
				"domain":   domain,
			}).Debug("User granted access via group membership")
			return nil
		}
	}

	return fmt.Errorf("user %s not in allowed groups for domain %s", user.Id, domain)
}

func (s *ProxyServiceServer) getAccountServiceByDomain(ctx context.Context, accountID, domain string) (*reverseproxy.Service, error) {
	services, err := s.reverseProxyManager.GetAccountServices(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("get account services: %w", err)
	}

	for _, service := range services {
		if service.Domain == domain {
			return service, nil
		}
	}

	return nil, fmt.Errorf("service not found for domain %s in account %s", domain, accountID)
}

// ValidateSession validates a session token and checks if the user has access to the domain.
func (s *ProxyServiceServer) ValidateSession(ctx context.Context, req *proto.ValidateSessionRequest) (*proto.ValidateSessionResponse, error) {
	domain := req.GetDomain()
	sessionToken := req.GetSessionToken()

	if domain == "" || sessionToken == "" {
		return &proto.ValidateSessionResponse{
			Valid:        false,
			DeniedReason: "missing domain or session_token",
		}, nil
	}

	service, err := s.getServiceByDomain(ctx, domain)
	if err != nil {
		log.WithFields(log.Fields{
			"domain": domain,
			"error":  err.Error(),
		}).Debug("ValidateSession: service not found")
		//nolint:nilerr
		return &proto.ValidateSessionResponse{
			Valid:        false,
			DeniedReason: "service_not_found",
		}, nil
	}

	pubKeyBytes, err := base64.StdEncoding.DecodeString(service.SessionPublicKey)
	if err != nil {
		log.WithFields(log.Fields{
			"domain": domain,
			"error":  err.Error(),
		}).Error("ValidateSession: decode public key")
		//nolint:nilerr
		return &proto.ValidateSessionResponse{
			Valid:        false,
			DeniedReason: "invalid_service_config",
		}, nil
	}

	userID, _, err := proxyauth.ValidateSessionJWT(sessionToken, domain, pubKeyBytes)
	if err != nil {
		log.WithFields(log.Fields{
			"domain": domain,
			"error":  err.Error(),
		}).Debug("ValidateSession: invalid session token")
		//nolint:nilerr
		return &proto.ValidateSessionResponse{
			Valid:        false,
			DeniedReason: "invalid_token",
		}, nil
	}

	user, err := s.usersManager.GetUser(ctx, userID)
	if err != nil {
		log.WithFields(log.Fields{
			"domain":  domain,
			"user_id": userID,
			"error":   err.Error(),
		}).Debug("ValidateSession: user not found")
		//nolint:nilerr
		return &proto.ValidateSessionResponse{
			Valid:        false,
			DeniedReason: "user_not_found",
		}, nil
	}

	if user.AccountID != service.AccountID {
		log.WithFields(log.Fields{
			"domain":          domain,
			"user_id":         userID,
			"user_account":    user.AccountID,
			"service_account": service.AccountID,
		}).Debug("ValidateSession: user account mismatch")
		//nolint:nilerr
		return &proto.ValidateSessionResponse{
			Valid:        false,
			DeniedReason: "account_mismatch",
		}, nil
	}

	if err := s.checkGroupAccess(service, user); err != nil {
		log.WithFields(log.Fields{
			"domain":  domain,
			"user_id": userID,
			"error":   err.Error(),
		}).Debug("ValidateSession: access denied")
		//nolint:nilerr
		return &proto.ValidateSessionResponse{
			Valid:        false,
			UserId:       user.Id,
			UserEmail:    user.Email,
			DeniedReason: "not_in_group",
		}, nil
	}

	log.WithFields(log.Fields{
		"domain":  domain,
		"user_id": userID,
		"email":   user.Email,
	}).Debug("ValidateSession: access granted")

	return &proto.ValidateSessionResponse{
		Valid:     true,
		UserId:    user.Id,
		UserEmail: user.Email,
	}, nil
}

func (s *ProxyServiceServer) getServiceByDomain(ctx context.Context, domain string) (*reverseproxy.Service, error) {
	services, err := s.reverseProxyManager.GetGlobalServices(ctx)
	if err != nil {
		return nil, fmt.Errorf("get services: %w", err)
	}

	for _, service := range services {
		if service.Domain == domain {
			return service, nil
		}
	}

	return nil, fmt.Errorf("service not found for domain: %s", domain)
}

func (s *ProxyServiceServer) checkGroupAccess(service *reverseproxy.Service, user *types.User) error {
	if service.Auth.BearerAuth == nil || !service.Auth.BearerAuth.Enabled {
		return nil
	}

	allowedGroups := service.Auth.BearerAuth.DistributionGroups
	if len(allowedGroups) == 0 {
		return nil
	}

	allowedSet := make(map[string]bool, len(allowedGroups))
	for _, groupID := range allowedGroups {
		allowedSet[groupID] = true
	}

	for _, groupID := range user.AutoGroups {
		if allowedSet[groupID] {
			return nil
		}
	}

	return fmt.Errorf("user not in allowed groups")
}
