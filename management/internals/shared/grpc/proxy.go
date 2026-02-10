package grpc

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
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

	"github.com/netbirdio/netbird/management/internals/modules/peers"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/accesslogs"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/sessionkey"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/management/server/users"
	proxyauth "github.com/netbirdio/netbird/proxy/auth"
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
	pkceVerifiers sync.Map
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

// NewProxyServiceServer creates a new proxy service server.
func NewProxyServiceServer(accessLogMgr accesslogs.Manager, tokenStore *OneTimeTokenStore, oidcConfig ProxyOIDCConfig, peersManager peers.Manager, usersManager users.Manager) *ProxyServiceServer {
	return &ProxyServiceServer{
		updatesChan:      make(chan *proto.ProxyMapping, 100),
		accessLogManager: accessLogMgr,
		oidcConfig:       oidcConfig,
		tokenStore:       tokenStore,
		peersManager:     peersManager,
		usersManager:     usersManager,
	}
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
	reverseProxies, err := s.reverseProxyManager.GetGlobalReverseProxies(ctx)
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

		// Generate one-time authentication token for each proxy in the snapshot
		// Tokens are not persistent on the proxy, so we need to generate new ones on reconnection
		token, err := s.tokenStore.GenerateToken(rp.AccountID, rp.ID, 5*time.Minute)
		if err != nil {
			log.WithFields(log.Fields{
				"proxy":   rp.Name,
				"account": rp.AccountID,
			}).WithError(err).Error("Failed to generate auth token for snapshot")
			continue
		}

		if err := conn.stream.Send(&proto.GetMappingUpdateResponse{
			Mapping: []*proto.ProxyMapping{
				rp.ToProtoMapping(
					reverseproxy.Create, // Initial snapshot, all records are "new" for the proxy.
					token,
					s.GetOIDCValidationConfig(),
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

	fields := log.Fields{
		"reverse_proxy_id": accessLog.GetServiceId(),
		"account_id":       accessLog.GetAccountId(),
		"host":             accessLog.GetHost(),
		"source_ip":        accessLog.GetSourceIp(),
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
	proxy, err := s.reverseProxyManager.GetProxyByID(ctx, req.GetAccountId(), req.GetId())
	if err != nil {
		// TODO: log the error
		return nil, status.Errorf(codes.FailedPrecondition, "failed to get reverse proxy from store: %v", err)
	}

	var authenticated bool
	var userId string
	var method proxyauth.Method
	switch v := req.GetRequest().(type) {
	case *proto.AuthenticateRequest_Pin:
		auth := proxy.Auth.PinAuth
		if auth == nil || !auth.Enabled {
			// TODO: log
			// Break here and use the default authenticated == false.
			break
		}
		authenticated = subtle.ConstantTimeCompare([]byte(auth.Pin), []byte(v.Pin.GetPin())) == 1
		userId = "pin-user"
		method = proxyauth.MethodPIN
	case *proto.AuthenticateRequest_Password:
		auth := proxy.Auth.PasswordAuth
		if auth == nil || !auth.Enabled {
			// TODO: log
			// Break here and use the default authenticated == false.
			break
		}
		authenticated = subtle.ConstantTimeCompare([]byte(auth.Password), []byte(v.Password.GetPassword())) == 1
		userId = "password-user"
		method = proxyauth.MethodPassword
	}

	var token string
	if authenticated && proxy.SessionPrivateKey != "" {
		token, err = sessionkey.SignToken(
			proxy.SessionPrivateKey,
			userId,
			proxy.Domain,
			method,
			proxyauth.DefaultSessionExpiry,
		)
		if err != nil {
			log.WithError(err).Error("Failed to sign session token")
			authenticated = false
		}
	}

	return &proto.AuthenticateResponse{
		Success:      authenticated,
		SessionToken: token,
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

// CreateProxyPeer handles proxy peer creation with one-time token authentication
func (s *ProxyServiceServer) CreateProxyPeer(ctx context.Context, req *proto.CreateProxyPeerRequest) (*proto.CreateProxyPeerResponse, error) {
	reverseProxyID := req.GetReverseProxyId()
	accountID := req.GetAccountId()
	token := req.GetToken()
	cluster := req.GetCluster()
	key := req.WireguardPublicKey

	log.WithFields(log.Fields{
		"reverse_proxy_id": reverseProxyID,
		"account_id":       accountID,
		"cluster":          cluster,
	}).Debug("CreateProxyPeer request received")

	if reverseProxyID == "" || accountID == "" || token == "" {
		log.Warn("CreateProxyPeer: missing required fields")
		return &proto.CreateProxyPeerResponse{
			Success:      false,
			ErrorMessage: strPtr("missing required fields: reverse_proxy_id, account_id, and token are required"),
		}, nil
	}

	if err := s.tokenStore.ValidateAndConsume(token, accountID, reverseProxyID); err != nil {
		log.WithFields(log.Fields{
			"reverse_proxy_id": reverseProxyID,
			"account_id":       accountID,
		}).WithError(err).Warn("CreateProxyPeer: token validation failed")
		return &proto.CreateProxyPeerResponse{
			Success:      false,
			ErrorMessage: strPtr("authentication failed: invalid or expired token"),
		}, status.Errorf(codes.Unauthenticated, "token validation failed: %v", err)
	}

	err := s.peersManager.CreateProxyPeer(ctx, accountID, key, cluster)
	if err != nil {
		log.WithFields(log.Fields{
			"reverse_proxy_id": reverseProxyID,
			"account_id":       accountID,
		}).WithError(err).Error("CreateProxyPeer: failed to create proxy peer")
		return &proto.CreateProxyPeerResponse{
			Success:      false,
			ErrorMessage: strPtr(fmt.Sprintf("failed to create proxy peer: %v", err)),
		}, status.Errorf(codes.Internal, "failed to create proxy peer: %v", err)
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
		// TODO: log
		return nil, status.Errorf(codes.InvalidArgument, "failed to parse redirect url: %v", err)
	}
	// Validate redirectURL against known proxy endpoints to avoid abuse of OIDC redirection.
	proxies, err := s.reverseProxyManager.GetAccountReverseProxies(ctx, req.GetAccountId())
	if err != nil {
		// TODO: log
		return nil, status.Errorf(codes.FailedPrecondition, "failed to get reverse proxy from store: %v", err)
	}
	var found bool
	for _, proxy := range proxies {
		if proxy.Domain == redirectURL.Hostname() {
			found = true
			break
		}
	}
	if !found {
		// TODO: log
		return nil, status.Errorf(codes.FailedPrecondition, "reverse proxy not found in store")
	}

	provider, err := oidc.NewProvider(ctx, s.oidcConfig.Issuer)
	if err != nil {
		// TODO: log
		return nil, status.Errorf(codes.FailedPrecondition, "failed to create OIDC provider: %v", err)
	}

	scopes := s.oidcConfig.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}

	// Using an HMAC here to avoid redirection state being modified.
	// State format: base64(redirectURL)|hmac
	hmacSum := s.generateHMAC(redirectURL.String())
	state := fmt.Sprintf("%s|%s", base64.URLEncoding.EncodeToString([]byte(redirectURL.String())), hmacSum)

	codeVerifier := oauth2.GenerateVerifier()
	s.pkceVerifiers.Store(state, codeVerifier)

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
	verifier, ok = v.(string)
	if !ok {
		return "", "", errors.New("invalid verifier for state")
	}

	parts := strings.Split(state, "|")
	if len(parts) != 2 {
		return "", "", errors.New("invalid state format")
	}

	encodedURL := parts[0]
	providedHMAC := parts[1]

	redirectURLBytes, err := base64.URLEncoding.DecodeString(encodedURL)
	if err != nil {
		return "", "", fmt.Errorf("invalid state encoding: %w", err)
	}
	redirectURL = string(redirectURLBytes)

	expectedHMAC := s.generateHMAC(redirectURL)

	if !hmac.Equal([]byte(providedHMAC), []byte(expectedHMAC)) {
		return "", "", fmt.Errorf("invalid state signature")
	}

	return verifier, redirectURL, nil
}

// GenerateSessionToken creates a signed session JWT for the given domain and user.
func (s *ProxyServiceServer) GenerateSessionToken(ctx context.Context, domain, userID string, method proxyauth.Method) (string, error) {
	// Find the proxy by domain to get its signing key
	proxies, err := s.reverseProxyManager.GetGlobalReverseProxies(ctx)
	if err != nil {
		return "", fmt.Errorf("get reverse proxies: %w", err)
	}

	var proxy *reverseproxy.ReverseProxy
	for _, p := range proxies {
		if p.Domain == domain {
			proxy = p
			break
		}
	}
	if proxy == nil {
		return "", fmt.Errorf("reverse proxy not found for domain: %s", domain)
	}

	if proxy.SessionPrivateKey == "" {
		return "", fmt.Errorf("no session key configured for domain: %s", domain)
	}

	return sessionkey.SignToken(
		proxy.SessionPrivateKey,
		userID,
		domain,
		method,
		proxyauth.DefaultSessionExpiry,
	)
}

// ValidateUserGroupAccess checks if a user has access to a reverse proxy.
// It looks up the proxy within the user's account only, then optionally checks
// group membership if BearerAuth with DistributionGroups is configured.
func (s *ProxyServiceServer) ValidateUserGroupAccess(ctx context.Context, domain, userID string) error {
	user, err := s.usersManager.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found: %s", userID)
	}

	proxy, err := s.getAccountProxyByDomain(ctx, user.AccountID, domain)
	if err != nil {
		return err
	}

	if proxy.Auth.BearerAuth == nil || !proxy.Auth.BearerAuth.Enabled {
		return nil
	}

	allowedGroups := proxy.Auth.BearerAuth.DistributionGroups
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

func (s *ProxyServiceServer) getAccountProxyByDomain(ctx context.Context, accountID, domain string) (*reverseproxy.ReverseProxy, error) {
	proxies, err := s.reverseProxyManager.GetAccountReverseProxies(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("get account reverse proxies: %w", err)
	}

	for _, proxy := range proxies {
		if proxy.Domain == domain {
			return proxy, nil
		}
	}

	return nil, fmt.Errorf("reverse proxy not found for domain %s in account %s", domain, accountID)
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

	proxy, err := s.getProxyByDomain(ctx, domain)
	if err != nil {
		log.WithFields(log.Fields{
			"domain": domain,
			"error":  err.Error(),
		}).Debug("ValidateSession: proxy not found")
		return &proto.ValidateSessionResponse{
			Valid:        false,
			DeniedReason: "proxy_not_found",
		}, nil
	}

	pubKeyBytes, err := base64.StdEncoding.DecodeString(proxy.SessionPublicKey)
	if err != nil {
		log.WithFields(log.Fields{
			"domain": domain,
			"error":  err.Error(),
		}).Error("ValidateSession: decode public key")
		return &proto.ValidateSessionResponse{
			Valid:        false,
			DeniedReason: "invalid_proxy_config",
		}, nil
	}

	userID, _, err := proxyauth.ValidateSessionJWT(sessionToken, domain, pubKeyBytes)
	if err != nil {
		log.WithFields(log.Fields{
			"domain": domain,
			"error":  err.Error(),
		}).Debug("ValidateSession: invalid session token")
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
		return &proto.ValidateSessionResponse{
			Valid:        false,
			DeniedReason: "user_not_found",
		}, nil
	}

	if user.AccountID != proxy.AccountID {
		log.WithFields(log.Fields{
			"domain":        domain,
			"user_id":       userID,
			"user_account":  user.AccountID,
			"proxy_account": proxy.AccountID,
		}).Debug("ValidateSession: user account mismatch")
		return &proto.ValidateSessionResponse{
			Valid:        false,
			DeniedReason: "account_mismatch",
		}, nil
	}

	if err := s.checkGroupAccess(proxy, user); err != nil {
		log.WithFields(log.Fields{
			"domain":  domain,
			"user_id": userID,
			"error":   err.Error(),
		}).Debug("ValidateSession: access denied")
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

func (s *ProxyServiceServer) getProxyByDomain(ctx context.Context, domain string) (*reverseproxy.ReverseProxy, error) {
	proxies, err := s.reverseProxyManager.GetGlobalReverseProxies(ctx)
	if err != nil {
		return nil, fmt.Errorf("get reverse proxies: %w", err)
	}

	for _, proxy := range proxies {
		if proxy.Domain == domain {
			return proxy, nil
		}
	}

	return nil, fmt.Errorf("reverse proxy not found for domain: %s", domain)
}

func (s *ProxyServiceServer) checkGroupAccess(proxy *reverseproxy.ReverseProxy, user *types.User) error {
	if proxy.Auth.BearerAuth == nil || !proxy.Auth.BearerAuth.Enabled {
		return nil
	}

	allowedGroups := proxy.Auth.BearerAuth.DistributionGroups
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
