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
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/shared/management/domain"

	"github.com/netbirdio/netbird/management/internals/modules/peers"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/accesslogs"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/sessionkey"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/management/server/users"
	proxyauth "github.com/netbirdio/netbird/proxy/auth"
	"github.com/netbirdio/netbird/shared/hash/argon2id"
	"github.com/netbirdio/netbird/shared/management/proto"
	nbstatus "github.com/netbirdio/netbird/shared/management/status"
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

// ProxyServiceServer implements the ProxyService gRPC server
type ProxyServiceServer struct {
	proto.UnimplementedProxyServiceServer

	// Map of connected proxies: proxy_id -> proxy connection
	connectedProxies sync.Map

	// Manager for access logs
	accessLogManager accesslogs.Manager

	mu sync.RWMutex
	// Manager for reverse proxy operations
	serviceManager rpservice.Manager
	// ProxyController for service updates and cluster management
	proxyController proxy.Controller

	// Manager for proxy connections
	proxyManager proxy.Manager

	// Manager for peers
	peersManager peers.Manager

	// Manager for users
	usersManager users.Manager

	// Store for one-time authentication tokens
	tokenStore *OneTimeTokenStore

	// OIDC configuration for proxy authentication
	oidcConfig ProxyOIDCConfig

	// Store for PKCE verifiers
	pkceVerifierStore *PKCEVerifierStore

	// tokenTTL is the lifetime of one-time tokens generated for proxy
	// authentication. Defaults to defaultProxyTokenTTL when zero.
	tokenTTL time.Duration

	// snapshotBatchSize is the number of mappings per gRPC message during
	// initial snapshot delivery. Configurable via NB_PROXY_SNAPSHOT_BATCH_SIZE.
	snapshotBatchSize int

	cancel context.CancelFunc
}

const pkceVerifierTTL = 10 * time.Minute

const defaultProxyTokenTTL = 5 * time.Minute

const defaultSnapshotBatchSize = 500

func snapshotBatchSizeFromEnv() int {
	if v := os.Getenv("NB_PROXY_SNAPSHOT_BATCH_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return defaultSnapshotBatchSize
}

// proxyTokenTTL returns the configured token TTL or the default when unset.
func (s *ProxyServiceServer) proxyTokenTTL() time.Duration {
	if s.tokenTTL > 0 {
		return s.tokenTTL
	}
	return defaultProxyTokenTTL
}

// proxyConnection represents a connected proxy
type proxyConnection struct {
	proxyID      string
	sessionID    string
	address      string
	capabilities *proto.ProxyCapabilities
	stream       proto.ProxyService_GetMappingUpdateServer
	sendChan     chan *proto.GetMappingUpdateResponse
	ctx          context.Context
	cancel       context.CancelFunc
}

// NewProxyServiceServer creates a new proxy service server.
func NewProxyServiceServer(accessLogMgr accesslogs.Manager, tokenStore *OneTimeTokenStore, pkceStore *PKCEVerifierStore, oidcConfig ProxyOIDCConfig, peersManager peers.Manager, usersManager users.Manager, proxyMgr proxy.Manager) *ProxyServiceServer {
	ctx, cancel := context.WithCancel(context.Background())
	s := &ProxyServiceServer{
		accessLogManager:  accessLogMgr,
		oidcConfig:        oidcConfig,
		tokenStore:        tokenStore,
		pkceVerifierStore: pkceStore,
		peersManager:      peersManager,
		usersManager:      usersManager,
		proxyManager:      proxyMgr,
		snapshotBatchSize: snapshotBatchSizeFromEnv(),
		cancel:            cancel,
	}
	go s.cleanupStaleProxies(ctx)
	return s
}

// cleanupStaleProxies periodically removes proxies that haven't sent heartbeat in 10 minutes
func (s *ProxyServiceServer) cleanupStaleProxies(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.proxyManager.CleanupStale(ctx, 1*time.Hour); err != nil {
				log.WithContext(ctx).Debugf("Failed to cleanup stale proxies: %v", err)
			}
		}
	}
}

// Close stops background goroutines.
func (s *ProxyServiceServer) Close() {
	s.cancel()
}

// SetServiceManager sets the service manager. Must be called before serving.
func (s *ProxyServiceServer) SetServiceManager(manager rpservice.Manager) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.serviceManager = manager
}

// SetProxyController sets the proxy controller. Must be called before serving.
func (s *ProxyServiceServer) SetProxyController(proxyController proxy.Controller) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.proxyController = proxyController
}

// GetMappingUpdate handles the control stream with proxy clients
func (s *ProxyServiceServer) GetMappingUpdate(req *proto.GetMappingUpdateRequest, stream proto.ProxyService_GetMappingUpdateServer) error {
	ctx := stream.Context()

	peerInfo := PeerIPFromContext(ctx)
	log.Infof("New proxy connection from %s", peerInfo)

	proxyID := req.GetProxyId()
	if proxyID == "" {
		return status.Errorf(codes.InvalidArgument, "proxy_id is required")
	}

	proxyAddress := req.GetAddress()
	if !isProxyAddressValid(proxyAddress) {
		return status.Errorf(codes.InvalidArgument, "proxy address is invalid")
	}

	sessionID := uuid.NewString()

	if old, loaded := s.connectedProxies.Load(proxyID); loaded {
		oldConn := old.(*proxyConnection)
		log.WithFields(log.Fields{
			"proxy_id":       proxyID,
			"old_session_id": oldConn.sessionID,
			"new_session_id": sessionID,
		}).Info("Superseding existing proxy connection")
		oldConn.cancel()
	}

	connCtx, cancel := context.WithCancel(ctx)
	conn := &proxyConnection{
		proxyID:      proxyID,
		sessionID:    sessionID,
		address:      proxyAddress,
		capabilities: req.GetCapabilities(),
		stream:       stream,
		sendChan:     make(chan *proto.GetMappingUpdateResponse, 100),
		ctx:          connCtx,
		cancel:       cancel,
	}

	// Register proxy in database with capabilities
	var caps *proxy.Capabilities
	if c := req.GetCapabilities(); c != nil {
		caps = &proxy.Capabilities{
			SupportsCustomPorts: c.SupportsCustomPorts,
			RequireSubdomain:    c.RequireSubdomain,
			SupportsCrowdsec:    c.SupportsCrowdsec,
		}
	}
	proxyRecord, err := s.proxyManager.Connect(ctx, proxyID, sessionID, proxyAddress, peerInfo, caps)
	if err != nil {
		log.WithContext(ctx).Warnf("failed to register proxy %s in database: %v", proxyID, err)
		cancel()
		return status.Errorf(codes.Internal, "register proxy in database: %v", err)
	}

	s.connectedProxies.Store(proxyID, conn)
	if err := s.proxyController.RegisterProxyToCluster(ctx, conn.address, proxyID); err != nil {
		log.WithContext(ctx).Warnf("Failed to register proxy %s in cluster: %v", proxyID, err)
	}

	if err := s.sendSnapshot(ctx, conn); err != nil {
		if s.connectedProxies.CompareAndDelete(proxyID, conn) {
			if unregErr := s.proxyController.UnregisterProxyFromCluster(context.Background(), conn.address, proxyID); unregErr != nil {
				log.WithContext(ctx).Debugf("cleanup after snapshot failure for proxy %s: %v", proxyID, unregErr)
			}
		}
		cancel()
		if disconnErr := s.proxyManager.Disconnect(context.Background(), proxyID, sessionID); disconnErr != nil {
			log.WithContext(ctx).Debugf("cleanup after snapshot failure for proxy %s: %v", proxyID, disconnErr)
		}
		return fmt.Errorf("send snapshot to proxy %s: %w", proxyID, err)
	}

	errChan := make(chan error, 2)
	go s.sender(conn, errChan)

	log.WithFields(log.Fields{
		"proxy_id":      proxyID,
		"session_id":    sessionID,
		"address":       proxyAddress,
		"cluster_addr":  proxyAddress,
		"total_proxies": len(s.GetConnectedProxies()),
	}).Info("Proxy registered in cluster")
	defer func() {
		if !s.connectedProxies.CompareAndDelete(proxyID, conn) {
			log.Infof("Proxy %s session %s: skipping cleanup, superseded by new connection", proxyID, sessionID)
			cancel()
			return
		}

		if err := s.proxyController.UnregisterProxyFromCluster(context.Background(), conn.address, proxyID); err != nil {
			log.Warnf("Failed to unregister proxy %s from cluster: %v", proxyID, err)
		}
		if err := s.proxyManager.Disconnect(context.Background(), proxyID, sessionID); err != nil {
			log.Warnf("Failed to mark proxy %s as disconnected: %v", proxyID, err)
		}

		cancel()
		log.Infof("Proxy %s session %s disconnected", proxyID, sessionID)
	}()

	go s.heartbeat(connCtx, proxyRecord)

	select {
	case err := <-errChan:
		log.WithContext(ctx).Warnf("Failed to send update: %v", err)
		return fmt.Errorf("send update to proxy %s: %w", proxyID, err)
	case <-connCtx.Done():
		log.WithContext(ctx).Infof("Proxy %s context canceled", proxyID)
		return connCtx.Err()
	}
}

// heartbeat updates the proxy's last_seen timestamp every minute
func (s *ProxyServiceServer) heartbeat(ctx context.Context, p *proxy.Proxy) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := s.proxyManager.Heartbeat(ctx, p); err != nil {
				log.WithContext(ctx).Debugf("Failed to update proxy %s heartbeat: %v", p.ID, err)
			}
		case <-ctx.Done():
			log.WithContext(ctx).Infof("proxy %s heartbeat stopped: context canceled", p.ID)
			return
		}
	}
}

// sendSnapshot sends the initial snapshot of services to the connecting proxy.
// Only entries matching the proxy's cluster address are sent.
func (s *ProxyServiceServer) sendSnapshot(ctx context.Context, conn *proxyConnection) error {
	if !isProxyAddressValid(conn.address) {
		return fmt.Errorf("proxy address is invalid")
	}

	mappings, err := s.snapshotServiceMappings(ctx, conn)
	if err != nil {
		return err
	}

	// Send mappings in batches to reduce per-message gRPC overhead while
	// staying well within the default 4 MB message size limit.
	for i := 0; i < len(mappings); i += s.snapshotBatchSize {
		end := i + s.snapshotBatchSize
		if end > len(mappings) {
			end = len(mappings)
		}
		if err := conn.stream.Send(&proto.GetMappingUpdateResponse{
			Mapping:             mappings[i:end],
			InitialSyncComplete: end == len(mappings),
		}); err != nil {
			return fmt.Errorf("send snapshot batch: %w", err)
		}
	}

	if len(mappings) == 0 {
		if err := conn.stream.Send(&proto.GetMappingUpdateResponse{
			InitialSyncComplete: true,
		}); err != nil {
			return fmt.Errorf("send snapshot completion: %w", err)
		}
	}

	return nil
}

func (s *ProxyServiceServer) snapshotServiceMappings(ctx context.Context, conn *proxyConnection) ([]*proto.ProxyMapping, error) {
	services, err := s.serviceManager.GetGlobalServices(ctx)
	if err != nil {
		return nil, fmt.Errorf("get services from store: %w", err)
	}

	var mappings []*proto.ProxyMapping
	for _, service := range services {
		if !service.Enabled || service.ProxyCluster == "" || service.ProxyCluster != conn.address {
			continue
		}

		token, err := s.tokenStore.GenerateToken(service.AccountID, service.ID, s.proxyTokenTTL())
		if err != nil {
			return nil, fmt.Errorf("generate auth token for service %s: %w", service.ID, err)
		}

		m := service.ToProtoMapping(rpservice.Create, token, s.GetOIDCValidationConfig())
		if !proxyAcceptsMapping(conn, m) {
			continue
		}
		mappings = append(mappings, m)
	}
	return mappings, nil
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
		case resp := <-conn.sendChan:
			if err := conn.stream.Send(resp); err != nil {
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
func (s *ProxyServiceServer) SendServiceUpdate(update *proto.GetMappingUpdateResponse) {
	log.Debugf("Broadcasting service update to all connected proxy servers")
	s.connectedProxies.Range(func(key, value interface{}) bool {
		conn := value.(*proxyConnection)
		resp := s.perProxyMessage(update, conn.proxyID)
		if resp == nil {
			log.Warnf("Token generation failed for proxy %s, disconnecting to force resync", conn.proxyID)
			conn.cancel()
			return true
		}
		select {
		case conn.sendChan <- resp:
			log.Debugf("Sent service update to proxy server %s", conn.proxyID)
		default:
			log.Warnf("Send channel full for proxy %s, disconnecting to force resync", conn.proxyID)
			conn.cancel()
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

// SendServiceUpdateToCluster sends a service update to all proxy servers in a specific cluster.
// If clusterAddr is empty, broadcasts to all connected proxy servers (backward compatibility).
// For create/update operations a unique one-time auth token is generated per
// proxy so that every replica can independently authenticate with management.
func (s *ProxyServiceServer) SendServiceUpdateToCluster(ctx context.Context, update *proto.ProxyMapping, clusterAddr string) {
	updateResponse := &proto.GetMappingUpdateResponse{
		Mapping: []*proto.ProxyMapping{update},
	}

	if clusterAddr == "" {
		s.SendServiceUpdate(updateResponse)
		return
	}

	if s.proxyController == nil {
		log.WithContext(ctx).Debugf("ProxyController not set, cannot send to cluster %s", clusterAddr)
		return
	}

	proxyIDs := s.proxyController.GetProxiesForCluster(clusterAddr)
	if len(proxyIDs) == 0 {
		log.WithContext(ctx).Debugf("No proxies connected for cluster %s", clusterAddr)
		return
	}

	log.Debugf("Sending service update to cluster %s", clusterAddr)
	for _, proxyID := range proxyIDs {
		connVal, ok := s.connectedProxies.Load(proxyID)
		if !ok {
			continue
		}
		conn := connVal.(*proxyConnection)
		if !proxyAcceptsMapping(conn, update) {
			log.WithContext(ctx).Debugf("Skipping proxy %s: does not support custom ports for mapping %s", proxyID, update.Id)
			continue
		}
		msg := s.perProxyMessage(updateResponse, proxyID)
		if msg == nil {
			log.WithContext(ctx).Warnf("Token generation failed for proxy %s in cluster %s, disconnecting to force resync", proxyID, clusterAddr)
			conn.cancel()
			continue
		}
		select {
		case conn.sendChan <- msg:
			log.WithContext(ctx).Debugf("Sent service update with id %s to proxy %s in cluster %s", update.Id, proxyID, clusterAddr)
		default:
			log.WithContext(ctx).Warnf("Send channel full for proxy %s in cluster %s, disconnecting to force resync", proxyID, clusterAddr)
			conn.cancel()
		}
	}
}

// proxyAcceptsMapping returns whether the proxy should receive this mapping.
// Old proxies that never reported capabilities are skipped for non-TLS L4
// mappings with a custom listen port, since they don't understand the
// protocol. Proxies that report capabilities (even SupportsCustomPorts=false)
// are new enough to handle the mapping. TLS uses SNI routing and works on
// any proxy. Delete operations are always sent so proxies can clean up.
func proxyAcceptsMapping(conn *proxyConnection, mapping *proto.ProxyMapping) bool {
	if mapping.Type == proto.ProxyMappingUpdateType_UPDATE_TYPE_REMOVED {
		return true
	}
	if mapping.ListenPort == 0 || mapping.Mode == "tls" {
		return true
	}
	// Old proxies that never reported capabilities don't understand
	// custom port mappings.
	return conn.capabilities != nil && conn.capabilities.SupportsCustomPorts != nil
}

// perProxyMessage returns a copy of update with a fresh one-time token for
// create/update operations. For delete operations the original mapping is
// used unchanged because proxies do not need to authenticate for removal.
// Returns nil if token generation fails; the caller must disconnect the
// proxy so it can resync via a fresh snapshot on reconnect.
func (s *ProxyServiceServer) perProxyMessage(update *proto.GetMappingUpdateResponse, proxyID string) *proto.GetMappingUpdateResponse {
	resp := make([]*proto.ProxyMapping, 0, len(update.Mapping))
	for _, mapping := range update.Mapping {
		if mapping.Type == proto.ProxyMappingUpdateType_UPDATE_TYPE_REMOVED {
			resp = append(resp, mapping)
			continue
		}

		token, err := s.tokenStore.GenerateToken(mapping.AccountId, mapping.Id, s.proxyTokenTTL())
		if err != nil {
			log.Warnf("Failed to generate token for proxy %s: %v", proxyID, err)
			return nil
		}

		msg := shallowCloneMapping(mapping)
		msg.AuthToken = token
		resp = append(resp, msg)
	}

	return &proto.GetMappingUpdateResponse{
		Mapping: resp,
	}
}

// shallowCloneMapping creates a shallow copy of a ProxyMapping, reusing the
// same slice/pointer fields. Only scalar fields that differ per proxy (AuthToken)
// should be set on the copy.
func shallowCloneMapping(m *proto.ProxyMapping) *proto.ProxyMapping {
	return &proto.ProxyMapping{
		Type:               m.Type,
		Id:                 m.Id,
		AccountId:          m.AccountId,
		Domain:             m.Domain,
		Path:               m.Path,
		Auth:               m.Auth,
		PassHostHeader:     m.PassHostHeader,
		RewriteRedirects:   m.RewriteRedirects,
		Mode:               m.Mode,
		ListenPort:         m.ListenPort,
		AccessRestrictions: m.AccessRestrictions,
	}
}

func (s *ProxyServiceServer) Authenticate(ctx context.Context, req *proto.AuthenticateRequest) (*proto.AuthenticateResponse, error) {
	service, err := s.serviceManager.GetServiceByID(ctx, req.GetAccountId(), req.GetId())
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

func (s *ProxyServiceServer) authenticateRequest(ctx context.Context, req *proto.AuthenticateRequest, service *rpservice.Service) (bool, string, proxyauth.Method) {
	switch v := req.GetRequest().(type) {
	case *proto.AuthenticateRequest_Pin:
		return s.authenticatePIN(ctx, req.GetId(), v, service.Auth.PinAuth)
	case *proto.AuthenticateRequest_Password:
		return s.authenticatePassword(ctx, req.GetId(), v, service.Auth.PasswordAuth)
	case *proto.AuthenticateRequest_HeaderAuth:
		return s.authenticateHeader(ctx, req.GetId(), v, service.Auth.HeaderAuths)
	default:
		return false, "", ""
	}
}

func (s *ProxyServiceServer) authenticatePIN(ctx context.Context, serviceID string, req *proto.AuthenticateRequest_Pin, auth *rpservice.PINAuthConfig) (bool, string, proxyauth.Method) {
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

func (s *ProxyServiceServer) authenticatePassword(ctx context.Context, serviceID string, req *proto.AuthenticateRequest_Password, auth *rpservice.PasswordAuthConfig) (bool, string, proxyauth.Method) {
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

func (s *ProxyServiceServer) authenticateHeader(ctx context.Context, serviceID string, req *proto.AuthenticateRequest_HeaderAuth, auths []*rpservice.HeaderAuthConfig) (bool, string, proxyauth.Method) {
	if len(auths) == 0 {
		log.WithContext(ctx).Debugf("header authentication attempted but no header auths configured for service %s", serviceID)
		return false, "", ""
	}

	headerName := http.CanonicalHeaderKey(req.HeaderAuth.GetHeaderName())

	var lastErr error
	for _, auth := range auths {
		if auth == nil || !auth.Enabled {
			continue
		}
		if headerName != "" && http.CanonicalHeaderKey(auth.Header) != headerName {
			continue
		}
		if err := argon2id.Verify(req.HeaderAuth.GetHeaderValue(), auth.Value); err != nil {
			lastErr = err
			continue
		}
		return true, "header-user", proxyauth.MethodHeader
	}

	if lastErr != nil {
		s.logAuthenticationError(ctx, lastErr, "Header")
	}
	return false, "", ""
}

func (s *ProxyServiceServer) logAuthenticationError(ctx context.Context, err error, authType string) {
	if errors.Is(err, argon2id.ErrMismatchedHashAndPassword) {
		log.WithContext(ctx).Tracef("%s authentication failed: invalid credentials", authType)
	} else {
		log.WithContext(ctx).Errorf("%s authentication error: %v", authType, err)
	}
}

func (s *ProxyServiceServer) generateSessionToken(ctx context.Context, authenticated bool, service *rpservice.Service, userId string, method proxyauth.Method) (string, error) {
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

// SendStatusUpdate handles status updates from proxy clients.
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

	internalStatus := protoStatusToInternal(protoStatus)

	if err := s.serviceManager.SetStatus(ctx, accountID, serviceID, internalStatus); err != nil {
		sErr, isNbErr := nbstatus.FromError(err)
		if isNbErr && sErr.Type() == nbstatus.NotFound {
			return nil, status.Errorf(codes.NotFound, "service %s not found", serviceID)
		}
		log.WithContext(ctx).WithError(err).Error("failed to update service status")
		return nil, status.Errorf(codes.Internal, "update service status: %v", err)
	}

	if certificateIssued {
		if err := s.serviceManager.SetCertificateIssuedAt(ctx, accountID, serviceID); err != nil {
			log.WithContext(ctx).WithError(err).Error("failed to set certificate issued timestamp")
			return nil, status.Errorf(codes.Internal, "update certificate timestamp: %v", err)
		}
		log.WithFields(log.Fields{
			"service_id": serviceID,
			"account_id": accountID,
		}).Info("Certificate issued timestamp updated")
	}

	log.WithFields(log.Fields{
		"service_id": serviceID,
		"account_id": accountID,
		"status":     internalStatus,
	}).Info("Service status updated")

	return &proto.SendStatusUpdateResponse{}, nil
}

// protoStatusToInternal maps proto status to internal service status.
func protoStatusToInternal(protoStatus proto.ProxyStatus) rpservice.Status {
	switch protoStatus {
	case proto.ProxyStatus_PROXY_STATUS_PENDING:
		return rpservice.StatusPending
	case proto.ProxyStatus_PROXY_STATUS_ACTIVE:
		return rpservice.StatusActive
	case proto.ProxyStatus_PROXY_STATUS_TUNNEL_NOT_CREATED:
		return rpservice.StatusTunnelNotCreated
	case proto.ProxyStatus_PROXY_STATUS_CERTIFICATE_PENDING:
		return rpservice.StatusCertificatePending
	case proto.ProxyStatus_PROXY_STATUS_CERTIFICATE_FAILED:
		return rpservice.StatusCertificateFailed
	case proto.ProxyStatus_PROXY_STATUS_ERROR:
		return rpservice.StatusError
	default:
		return rpservice.StatusError
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
	if redirectURL.Scheme != "https" && redirectURL.Scheme != "http" {
		return nil, status.Errorf(codes.InvalidArgument, "redirect URL must use http or https scheme")
	}
	// Validate redirectURL against known service endpoints to avoid abuse of OIDC redirection.
	services, err := s.serviceManager.GetAccountServices(ctx, req.GetAccountId())
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
	if err := s.pkceVerifierStore.Store(state, codeVerifier, pkceVerifierTTL); err != nil {
		log.WithContext(ctx).Errorf("failed to store PKCE verifier: %v", err)
		return nil, status.Errorf(codes.Internal, "store PKCE verifier: %v", err)
	}

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
func (s *ProxyServiceServer) GetOIDCValidationConfig() proxy.OIDCValidationConfig {
	return proxy.OIDCValidationConfig{
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
// The HMAC is verified before consuming the PKCE verifier to prevent
// an attacker from invalidating a legitimate user's auth flow.
func (s *ProxyServiceServer) ValidateState(state string) (verifier, redirectURL string, err error) {
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

	// Consume the PKCE verifier only after HMAC validation passes.
	verifier, ok := s.pkceVerifierStore.LoadAndDelete(state)
	if !ok {
		return "", "", errors.New("no verifier for state")
	}

	return verifier, redirectURL, nil
}

// GenerateSessionToken creates a signed session JWT for the given domain and user.
func (s *ProxyServiceServer) GenerateSessionToken(ctx context.Context, domain, userID string, method proxyauth.Method) (string, error) {
	// Find the service by domain to get its signing key
	services, err := s.serviceManager.GetGlobalServices(ctx)
	if err != nil {
		return "", fmt.Errorf("get services: %w", err)
	}

	var service *rpservice.Service
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

func (s *ProxyServiceServer) getAccountServiceByDomain(ctx context.Context, accountID, domain string) (*rpservice.Service, error) {
	services, err := s.serviceManager.GetAccountServices(ctx, accountID)
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

func (s *ProxyServiceServer) getServiceByDomain(ctx context.Context, domain string) (*rpservice.Service, error) {
	services, err := s.serviceManager.GetGlobalServices(ctx)
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

func (s *ProxyServiceServer) checkGroupAccess(service *rpservice.Service, user *types.User) error {
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

func ptr[T any](v T) *T { return &v }
