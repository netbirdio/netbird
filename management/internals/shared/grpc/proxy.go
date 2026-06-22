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
	"io"
	"net"
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
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/peer"
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

// ProxyTokenChecker checks whether a proxy access token is still valid.
type ProxyTokenChecker interface {
	IsProxyAccessTokenValid(ctx context.Context, tokenID string) (bool, error)
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

	// Manager for IdP-enriched user data (may be nil when no IdP is configured)
	idpManager idp.Manager

	// Store for one-time authentication tokens
	tokenStore *OneTimeTokenStore

	// Checker for proxy access token validity
	tokenChecker ProxyTokenChecker

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
	accountID    *string
	tokenID      string
	capabilities *proto.ProxyCapabilities
	stream       proto.ProxyService_GetMappingUpdateServer
	// syncStream is set when the proxy connected via SyncMappings.
	// When non-nil, the sender goroutine uses this instead of stream.
	syncStream proto.ProxyService_SyncMappingsServer
	sendChan   chan *proto.GetMappingUpdateResponse
	ctx        context.Context
	cancel     context.CancelFunc
}

func enforceAccountScope(ctx context.Context, requestAccountID string) error {
	token := GetProxyTokenFromContext(ctx)
	if token == nil || token.AccountID == nil {
		return nil
	}
	if requestAccountID == "" || *token.AccountID != requestAccountID {
		return status.Errorf(codes.PermissionDenied, "account-scoped token cannot access account %s", requestAccountID)
	}
	return nil
}

// NewProxyServiceServer creates a new proxy service server.
func NewProxyServiceServer(accessLogMgr accesslogs.Manager, tokenStore *OneTimeTokenStore, pkceStore *PKCEVerifierStore, oidcConfig ProxyOIDCConfig, peersManager peers.Manager, usersManager users.Manager, idpManager idp.Manager, proxyMgr proxy.Manager, tokenChecker ProxyTokenChecker) *ProxyServiceServer {
	ctx, cancel := context.WithCancel(context.Background())
	s := &ProxyServiceServer{
		accessLogManager:  accessLogMgr,
		oidcConfig:        oidcConfig,
		tokenStore:        tokenStore,
		pkceVerifierStore: pkceStore,
		peersManager:      peersManager,
		usersManager:      usersManager,
		idpManager:        idpManager,
		proxyManager:      proxyMgr,
		tokenChecker:      tokenChecker,
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

// proxyConnectParams holds the validated parameters extracted from either
// a GetMappingUpdateRequest or a SyncMappingsInit message.
type proxyConnectParams struct {
	proxyID      string
	address      string
	capabilities *proto.ProxyCapabilities
}

// GetMappingUpdate handles the control stream with proxy clients
func (s *ProxyServiceServer) GetMappingUpdate(req *proto.GetMappingUpdateRequest, stream proto.ProxyService_GetMappingUpdateServer) error {
	params, err := s.validateProxyConnect(req.GetProxyId(), req.GetAddress(), stream.Context())
	if err != nil {
		return err
	}
	params.capabilities = req.GetCapabilities()

	conn, proxyRecord, err := s.registerProxyConnection(stream.Context(), params, &proxyConnection{
		stream: stream,
	})
	if err != nil {
		return err
	}

	if err := s.sendSnapshot(stream.Context(), conn); err != nil {
		s.cleanupFailedSnapshot(stream.Context(), conn)
		return fmt.Errorf("send snapshot to proxy %s: %w", params.proxyID, err)
	}

	errChan := make(chan error, 2)
	go s.sender(conn, errChan)

	return s.serveProxyConnection(conn, proxyRecord, errChan, false)
}

// SyncMappings implements the bidirectional SyncMappings RPC.
// It mirrors GetMappingUpdate but provides application-level back-pressure:
// management waits for an ack from the proxy before sending the next batch.
func (s *ProxyServiceServer) SyncMappings(stream proto.ProxyService_SyncMappingsServer) error {
	init, err := recvSyncInit(stream)
	if err != nil {
		return err
	}

	params, err := s.validateProxyConnect(init.GetProxyId(), init.GetAddress(), stream.Context())
	if err != nil {
		return err
	}
	params.capabilities = init.GetCapabilities()

	conn, proxyRecord, err := s.registerProxyConnection(stream.Context(), params, &proxyConnection{
		syncStream: stream,
	})
	if err != nil {
		return err
	}

	if err := s.sendSnapshotSync(stream.Context(), conn, stream); err != nil {
		s.cleanupFailedSnapshot(stream.Context(), conn)
		return fmt.Errorf("send snapshot to proxy %s: %w", params.proxyID, err)
	}

	errChan := make(chan error, 2)
	go s.sender(conn, errChan)
	go s.drainRecv(stream, errChan)

	return s.serveProxyConnection(conn, proxyRecord, errChan, true)
}

// recvSyncInit receives and validates the first message on a SyncMappings stream.
func recvSyncInit(stream proto.ProxyService_SyncMappingsServer) (*proto.SyncMappingsInit, error) {
	firstMsg, err := stream.Recv()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "receive init: %v", err)
	}
	init := firstMsg.GetInit()
	if init == nil {
		return nil, status.Errorf(codes.InvalidArgument, "first message must be init")
	}
	return init, nil
}

// validateProxyConnect validates the proxy ID and address, and checks cluster
// address availability for account-scoped tokens.
func (s *ProxyServiceServer) validateProxyConnect(proxyID, address string, ctx context.Context) (proxyConnectParams, error) {
	if proxyID == "" {
		return proxyConnectParams{}, status.Errorf(codes.InvalidArgument, "proxy_id is required")
	}
	if !isProxyAddressValid(address) {
		return proxyConnectParams{}, status.Errorf(codes.InvalidArgument, "proxy address is invalid")
	}

	token := GetProxyTokenFromContext(ctx)
	if token != nil && token.AccountID != nil {
		available, err := s.proxyManager.IsClusterAddressAvailable(ctx, address, *token.AccountID)
		if err != nil {
			return proxyConnectParams{}, status.Errorf(codes.Internal, "check cluster address: %v", err)
		}
		if !available {
			return proxyConnectParams{}, status.Errorf(codes.AlreadyExists, "cluster address %s is already in use", address)
		}
	}

	return proxyConnectParams{proxyID: proxyID, address: address}, nil
}

// registerProxyConnection creates a proxyConnection, registers it with the
// proxy manager and cluster, and stores it in connectedProxies. The caller
// provides a partially initialised connSeed with stream-specific fields set;
// the remaining fields are filled in here.
func (s *ProxyServiceServer) registerProxyConnection(ctx context.Context, params proxyConnectParams, connSeed *proxyConnection) (*proxyConnection, *proxy.Proxy, error) {
	peerInfo := PeerIPFromContext(ctx)

	var accountID *string
	var tokenID string
	if token := GetProxyTokenFromContext(ctx); token != nil {
		if token.AccountID != nil {
			accountID = token.AccountID
		}
		tokenID = token.ID
	}

	sessionID := uuid.NewString()
	s.supersedePriorConnection(params.proxyID, sessionID)

	connCtx, cancel := context.WithCancel(ctx)
	connSeed.proxyID = params.proxyID
	connSeed.sessionID = sessionID
	connSeed.address = params.address
	connSeed.accountID = accountID
	connSeed.tokenID = tokenID
	connSeed.capabilities = params.capabilities
	connSeed.sendChan = make(chan *proto.GetMappingUpdateResponse, 100)
	connSeed.ctx = connCtx
	connSeed.cancel = cancel

	var caps *proxy.Capabilities
	if c := params.capabilities; c != nil {
		caps = &proxy.Capabilities{
			SupportsCustomPorts: c.SupportsCustomPorts,
			RequireSubdomain:    c.RequireSubdomain,
			SupportsCrowdsec:    c.SupportsCrowdsec,
			Private:             c.Private,
		}
	}

	proxyRecord, err := s.proxyManager.Connect(ctx, params.proxyID, sessionID, params.address, peerInfo, accountID, caps)
	if err != nil {
		cancel()
		if accountID != nil {
			return nil, nil, status.Errorf(codes.Internal, "failed to register BYOP proxy: %v", err)
		}
		log.WithContext(ctx).Warnf("failed to register proxy %s in database: %v", params.proxyID, err)
		return nil, nil, status.Errorf(codes.Internal, "register proxy in database: %v", err)
	}

	s.connectedProxies.Store(params.proxyID, connSeed)
	if err := s.proxyController.RegisterProxyToCluster(ctx, params.address, params.proxyID); err != nil {
		log.WithContext(ctx).Warnf("Failed to register proxy %s in cluster: %v", params.proxyID, err)
	}

	return connSeed, proxyRecord, nil
}

// supersedePriorConnection cancels any existing connection for the given proxy.
func (s *ProxyServiceServer) supersedePriorConnection(proxyID, newSessionID string) {
	if old, loaded := s.connectedProxies.Load(proxyID); loaded {
		oldConn := old.(*proxyConnection)
		log.WithFields(log.Fields{
			"proxy_id":       proxyID,
			"old_session_id": oldConn.sessionID,
			"new_session_id": newSessionID,
		}).Info("Superseding existing proxy connection")
		oldConn.cancel()
	}
}

// cleanupFailedSnapshot removes the connection from the cluster and store
// after a snapshot send failure.
func (s *ProxyServiceServer) cleanupFailedSnapshot(ctx context.Context, conn *proxyConnection) {
	if s.connectedProxies.CompareAndDelete(conn.proxyID, conn) {
		if err := s.proxyController.UnregisterProxyFromCluster(context.Background(), conn.address, conn.proxyID); err != nil {
			log.WithContext(ctx).Debugf("cleanup after snapshot failure for proxy %s: %v", conn.proxyID, err)
		}
	}
	conn.cancel()
	if err := s.proxyManager.Disconnect(context.Background(), conn.proxyID, conn.sessionID); err != nil {
		log.WithContext(ctx).Debugf("cleanup after snapshot failure for proxy %s: %v", conn.proxyID, err)
	}
}

// drainRecv consumes and discards messages from a bidirectional stream.
// The proxy sends an ack for every incremental update; we don't need them
// after the snapshot phase. Recv errors are forwarded to errChan.
func (s *ProxyServiceServer) drainRecv(stream proto.ProxyService_SyncMappingsServer, errChan chan<- error) {
	for {
		if _, err := stream.Recv(); err != nil {
			errChan <- err
			return
		}
	}
}

// serveProxyConnection runs the post-snapshot lifecycle: heartbeat, sender,
// and wait for termination. When bidi is true, normal stream closure (EOF,
// canceled) is treated as a clean disconnect rather than an error.
func (s *ProxyServiceServer) serveProxyConnection(conn *proxyConnection, proxyRecord *proxy.Proxy, errChan <-chan error, bidi bool) error {
	log.WithFields(log.Fields{
		"proxy_id":      conn.proxyID,
		"session_id":    conn.sessionID,
		"address":       conn.address,
		"cluster_addr":  conn.address,
		"account_id":    conn.accountID,
		"total_proxies": len(s.GetConnectedProxies()),
	}).Info("Proxy registered in cluster")

	defer s.disconnectProxy(conn)
	go s.heartbeat(conn.ctx, conn, proxyRecord)

	select {
	case err := <-errChan:
		if bidi && isStreamClosed(err) {
			log.Infof("Proxy %s stream closed", conn.proxyID)
			return nil
		}
		log.Warnf("Failed to send update: %v", err)
		return fmt.Errorf("send update to proxy %s: %w", conn.proxyID, err)
	case <-conn.ctx.Done():
		log.Infof("Proxy %s context canceled", conn.proxyID)
		return conn.ctx.Err()
	}
}

// disconnectProxy removes the connection from cluster and store, unless it
// has already been superseded by a newer connection.
func (s *ProxyServiceServer) disconnectProxy(conn *proxyConnection) {
	if !s.connectedProxies.CompareAndDelete(conn.proxyID, conn) {
		log.Infof("Proxy %s session %s: skipping cleanup, superseded by new connection", conn.proxyID, conn.sessionID)
		conn.cancel()
		return
	}

	if err := s.proxyController.UnregisterProxyFromCluster(context.Background(), conn.address, conn.proxyID); err != nil {
		log.Warnf("Failed to unregister proxy %s from cluster: %v", conn.proxyID, err)
	}
	if err := s.proxyManager.Disconnect(context.Background(), conn.proxyID, conn.sessionID); err != nil {
		log.Warnf("Failed to mark proxy %s as disconnected: %v", conn.proxyID, err)
	}

	conn.cancel()
	log.Infof("Proxy %s session %s disconnected", conn.proxyID, conn.sessionID)
}

// sendSnapshotSync sends the initial snapshot with back-pressure: it sends
// one batch, then waits for the proxy to ack before sending the next.
func (s *ProxyServiceServer) sendSnapshotSync(ctx context.Context, conn *proxyConnection, stream proto.ProxyService_SyncMappingsServer) error {
	if !isProxyAddressValid(conn.address) {
		return fmt.Errorf("proxy address is invalid")
	}
	if s.snapshotBatchSize <= 0 {
		return fmt.Errorf("invalid snapshot batch size: %d", s.snapshotBatchSize)
	}

	mappings, err := s.snapshotServiceMappings(ctx, conn)
	if err != nil {
		return err
	}

	for i := 0; i < len(mappings); i += s.snapshotBatchSize {
		end := i + s.snapshotBatchSize
		if end > len(mappings) {
			end = len(mappings)
		}
		for _, m := range mappings[i:end] {
			token, err := s.tokenStore.GenerateToken(m.AccountId, m.Id, s.proxyTokenTTL())
			if err != nil {
				return fmt.Errorf("generate auth token for service %s: %w", m.Id, err)
			}
			m.AuthToken = token
		}
		if err := stream.Send(&proto.SyncMappingsResponse{
			Mapping:             mappings[i:end],
			InitialSyncComplete: end == len(mappings),
		}); err != nil {
			return fmt.Errorf("send snapshot batch: %w", err)
		}

		if err := waitForAck(stream); err != nil {
			return err
		}
	}

	if len(mappings) == 0 {
		if err := stream.Send(&proto.SyncMappingsResponse{
			InitialSyncComplete: true,
		}); err != nil {
			return fmt.Errorf("send snapshot completion: %w", err)
		}

		if err := waitForAck(stream); err != nil {
			return err
		}
	}

	return nil
}

func waitForAck(stream proto.ProxyService_SyncMappingsServer) error {
	msg, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("receive ack: %w", err)
	}
	if msg.GetAck() == nil {
		return fmt.Errorf("expected ack, got %T", msg.GetMsg())
	}
	return nil
}

// heartbeat updates the proxy's last_seen timestamp every minute and
// disconnects the proxy if its access token has been revoked.
func (s *ProxyServiceServer) heartbeat(ctx context.Context, conn *proxyConnection, p *proxy.Proxy) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := s.proxyManager.Heartbeat(ctx, p); err != nil {
				log.WithContext(ctx).Debugf("Failed to update proxy %s heartbeat: %v", p.ID, err)
			}

			if conn.tokenID != "" && s.tokenChecker != nil {
				valid, err := s.tokenChecker.IsProxyAccessTokenValid(ctx, conn.tokenID)
				if err != nil {
					log.WithContext(ctx).Warnf("failed to check token validity for proxy %s: %v", conn.proxyID, err)
					continue
				}
				if !valid {
					log.WithContext(ctx).Warnf("proxy %s token revoked or expired, disconnecting", conn.proxyID)
					conn.cancel()
					return
				}
			}
		case <-ctx.Done():
			log.WithContext(ctx).Infof("proxy %s heartbeat stopped: context canceled", p.ID)
			return
		}
	}
}

func (s *ProxyServiceServer) sendSnapshot(ctx context.Context, conn *proxyConnection) error {
	if !isProxyAddressValid(conn.address) {
		return fmt.Errorf("proxy address is invalid")
	}
	if s.snapshotBatchSize <= 0 {
		return fmt.Errorf("invalid snapshot batch size: %d", s.snapshotBatchSize)
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
		for _, m := range mappings[i:end] {
			token, err := s.tokenStore.GenerateToken(m.AccountId, m.Id, s.proxyTokenTTL())
			if err != nil {
				return fmt.Errorf("generate auth token for service %s: %w", m.Id, err)
			}
			m.AuthToken = token
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
	var services []*rpservice.Service
	var err error
	if conn.accountID != nil {
		services, err = s.serviceManager.GetAccountServices(ctx, *conn.accountID)
	} else {
		services, err = s.serviceManager.GetGlobalServices(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("get services from store: %w", err)
	}

	oidcCfg := s.GetOIDCValidationConfig()
	var mappings []*proto.ProxyMapping
	for _, service := range services {
		if !service.Enabled || service.ProxyCluster == "" || service.ProxyCluster != conn.address {
			continue
		}

		m := service.ToProtoMapping(rpservice.Create, "", oidcCfg)
		if !proxyAcceptsMapping(conn, m) {
			continue
		}
		mappings = append(mappings, m)
	}
	return mappings, nil
}

// isProxyAddressValid validates a proxy address (domain name or IP address)
func isProxyAddressValid(addr string) bool {
	if addr == "" {
		return false
	}
	if net.ParseIP(addr) != nil {
		return true
	}
	_, err := domain.ValidateDomains([]string{addr})
	return err == nil
}

// isStreamClosed returns true for errors that indicate normal stream
// termination: io.EOF, context cancellation, or gRPC Canceled.
func isStreamClosed(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
		return true
	}
	return status.Code(err) == codes.Canceled
}

// sender handles sending messages to proxy.
// When conn.syncStream is set the message is sent as SyncMappingsResponse;
// otherwise the legacy GetMappingUpdateResponse stream is used.
func (s *ProxyServiceServer) sender(conn *proxyConnection, errChan chan<- error) {
	for {
		select {
		case resp := <-conn.sendChan:
			if err := conn.sendResponse(resp); err != nil {
				errChan <- err
				log.WithContext(conn.ctx).Tracef("Failed to send response to proxy %s: %v", conn.proxyID, err)
				return
			}
			log.WithContext(conn.ctx).Tracef("Send response to proxy %s", conn.proxyID)
		case <-conn.ctx.Done():
			return
		}
	}
}

// sendResponse sends a mapping update on whichever stream the proxy connected with.
func (conn *proxyConnection) sendResponse(resp *proto.GetMappingUpdateResponse) error {
	if conn.syncStream != nil {
		return conn.syncStream.Send(&proto.SyncMappingsResponse{
			Mapping:             resp.Mapping,
			InitialSyncComplete: resp.InitialSyncComplete,
		})
	}
	return conn.stream.Send(resp)
}

// SendAccessLog processes access log from proxy
func (s *ProxyServiceServer) SendAccessLog(ctx context.Context, req *proto.SendAccessLogRequest) (*proto.SendAccessLogResponse, error) {
	accessLog := req.GetLog()

	if err := enforceAccountScope(ctx, accessLog.GetAccountId()); err != nil {
		return nil, err
	}

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
// BYOP proxies only receive updates for their own account's services.
func (s *ProxyServiceServer) SendServiceUpdate(update *proto.GetMappingUpdateResponse) {
	log.Debugf("Broadcasting service update to all connected proxy servers")
	updateAccountIDs := make(map[string]struct{})
	for _, m := range update.Mapping {
		if m.AccountId != "" {
			updateAccountIDs[m.AccountId] = struct{}{}
		}
	}
	s.connectedProxies.Range(func(key, value interface{}) bool {
		conn := value.(*proxyConnection)
		connUpdate := update
		if conn.accountID != nil && len(updateAccountIDs) > 0 {
			if _, ok := updateAccountIDs[*conn.accountID]; !ok {
				return true
			}
			filtered := filterMappingsForAccount(update.Mapping, *conn.accountID)
			if len(filtered) == 0 {
				return true
			}
			connUpdate = &proto.GetMappingUpdateResponse{
				Mapping:             filtered,
				InitialSyncComplete: update.InitialSyncComplete,
			}
		}
		// Drop mappings the proxy lacks capability for (e.g. private without SupportsPrivateService).
		connUpdate = filterMappingsForProxy(conn, connUpdate)
		if connUpdate == nil || len(connUpdate.Mapping) == 0 {
			return true
		}
		resp := s.perProxyMessage(connUpdate, conn.proxyID)
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

// ForceDisconnect cancels the gRPC stream for a connected proxy, causing it to disconnect.
func (s *ProxyServiceServer) ForceDisconnect(proxyID string) {
	if connVal, ok := s.connectedProxies.Load(proxyID); ok {
		conn := connVal.(*proxyConnection)
		conn.cancel()
		s.connectedProxies.Delete(proxyID)
		log.WithFields(log.Fields{"proxyID": proxyID}).Info("force disconnected proxy")
	}
}

func filterMappingsForAccount(mappings []*proto.ProxyMapping, accountID string) []*proto.ProxyMapping {
	var filtered []*proto.ProxyMapping
	for _, m := range mappings {
		if m.AccountId == accountID {
			filtered = append(filtered, m)
		}
	}
	return filtered
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
		if conn.accountID != nil && update.AccountId != "" && *conn.accountID != update.AccountId {
			continue
		}
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

// proxyAcceptsMapping returns whether the proxy can receive this mapping.
// Private mappings require SupportsPrivateService; custom-port L4 mappings
// require SupportsCustomPorts. Remove operations always pass so proxies can
// clean up.
func proxyAcceptsMapping(conn *proxyConnection, mapping *proto.ProxyMapping) bool {
	if mapping.Type == proto.ProxyMappingUpdateType_UPDATE_TYPE_REMOVED {
		return true
	}
	if mapping.GetPrivate() {
		caps := conn.capabilities
		if caps == nil || caps.SupportsPrivateService == nil || !*caps.SupportsPrivateService {
			return false
		}
	}
	if mapping.ListenPort == 0 || mapping.Mode == "tls" {
		return true
	}
	// Old proxies that never reported capabilities don't understand
	// custom port mappings.
	return conn.capabilities != nil && conn.capabilities.SupportsCustomPorts != nil
}

// filterMappingsForProxy drops mappings the proxy cannot safely receive
// (e.g. private mappings to a proxy without SupportsPrivateService).
// Returns the input unchanged when no filtering is needed.
func filterMappingsForProxy(conn *proxyConnection, update *proto.GetMappingUpdateResponse) *proto.GetMappingUpdateResponse {
	if update == nil || len(update.Mapping) == 0 {
		return update
	}
	kept := make([]*proto.ProxyMapping, 0, len(update.Mapping))
	for _, m := range update.Mapping {
		if !proxyAcceptsMapping(conn, m) {
			continue
		}
		kept = append(kept, m)
	}
	if len(kept) == len(update.Mapping) {
		return update
	}
	return &proto.GetMappingUpdateResponse{
		Mapping:             kept,
		InitialSyncComplete: update.InitialSyncComplete,
	}
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
		Private:            m.Private,
	}
}

func (s *ProxyServiceServer) Authenticate(ctx context.Context, req *proto.AuthenticateRequest) (*proto.AuthenticateResponse, error) {
	if err := enforceAccountScope(ctx, req.GetAccountId()); err != nil {
		return nil, err
	}

	service, err := s.serviceManager.GetServiceByID(ctx, req.GetAccountId(), req.GetId())
	if err != nil {
		log.WithContext(ctx).Debugf("failed to get service from store: %v", err)
		return nil, status.Errorf(codes.FailedPrecondition, "get service from store: %v", err)
	}

	authenticated, userId, method := s.authenticateRequest(ctx, req, service)

	// Non-OIDC schemes (PIN/Password/Header) authenticate against per-service
	// secrets and have no user-level group context, so groups stay nil. Email
	// is also empty — these schemes don't resolve a user record at sign time.
	token, err := s.generateSessionToken(ctx, authenticated, service, userId, "", method, nil, nil)
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

func (s *ProxyServiceServer) generateSessionToken(ctx context.Context, authenticated bool, service *rpservice.Service, userId, userEmail string, method proxyauth.Method, groupIDs, groupNames []string) (string, error) {
	if !authenticated || service.SessionPrivateKey == "" {
		return "", nil
	}

	token, err := sessionkey.SignToken(
		service.SessionPrivateKey,
		userId,
		userEmail,
		service.Domain,
		method,
		groupIDs,
		groupNames,
		proxyauth.DefaultSessionExpiry,
	)
	if err != nil {
		log.WithContext(ctx).WithError(err).Error("failed to sign session token")
		return "", status.Errorf(codes.Internal, "sign session token: %v", err)
	}

	return token, nil
}

// pairGroupIDsAndNames splits a slice of resolved *types.Group records
// into parallel id and name slices. ids[i] and names[i] always pair to
// the same group. nil entries (orphan ids the manager couldn't resolve)
// are skipped so the consumer can rely on positional pairing.
func pairGroupIDsAndNames(groups []*types.Group) (ids, names []string) {
	if len(groups) == 0 {
		return nil, nil
	}
	ids = make([]string, 0, len(groups))
	names = make([]string, 0, len(groups))
	for _, g := range groups {
		if g == nil {
			continue
		}
		ids = append(ids, g.ID)
		names = append(names, g.Name)
	}
	return ids, names
}

// SendStatusUpdate handles status updates from proxy clients.
func (s *ProxyServiceServer) SendStatusUpdate(ctx context.Context, req *proto.SendStatusUpdateRequest) (*proto.SendStatusUpdateResponse, error) {
	if err := enforceAccountScope(ctx, req.GetAccountId()); err != nil {
		return nil, err
	}

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
	if err := enforceAccountScope(ctx, req.GetAccountId()); err != nil {
		return nil, err
	}

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
	if err := enforceAccountScope(ctx, req.GetAccountId()); err != nil {
		return nil, err
	}

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

// GenerateSessionToken creates a signed session JWT for the given domain and
// user. The user's group memberships are embedded in the token so policy-aware
// middlewares on the proxy can authorise without an extra management round-trip.
func (s *ProxyServiceServer) GenerateSessionToken(ctx context.Context, domain, userID string, method proxyauth.Method) (string, error) {
	service, err := s.getServiceByDomain(ctx, domain)
	if err != nil {
		return "", fmt.Errorf("service not found for domain %s: %w", domain, err)
	}

	if service.SessionPrivateKey == "" {
		return "", fmt.Errorf("no session key configured for domain: %s", domain)
	}

	var (
		email      string
		groupIDs   []string
		groupNames []string
	)
	if s.usersManager != nil {
		user, userGroups, uerr := s.usersManager.GetUserWithGroups(ctx, userID)
		if uerr != nil {
			log.WithContext(ctx).Debugf("session token mint: lookup user %s: %v", userID, uerr)
		} else if user != nil {
			email = user.Email
			groupIDs, groupNames = pairGroupIDsAndNames(userGroups)
		}
	}

	return sessionkey.SignToken(
		service.SessionPrivateKey,
		userID,
		email,
		domain,
		method,
		groupIDs,
		groupNames,
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

	if err := enforceAccountScope(ctx, service.AccountID); err != nil {
		return nil, err
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

	userID, _, _, _, _, err := proxyauth.ValidateSessionJWT(sessionToken, domain, pubKeyBytes)
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

	user, userGroups, err := s.usersManager.GetUserWithGroups(ctx, userID)
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
		groupIDs, groupNames := pairGroupIDsAndNames(userGroups)
		//nolint:nilerr
		return &proto.ValidateSessionResponse{
			Valid:          false,
			UserId:         user.Id,
			UserEmail:      user.Email,
			DeniedReason:   "not_in_group",
			PeerGroupIds:   groupIDs,
			PeerGroupNames: groupNames,
		}, nil
	}

	log.WithFields(log.Fields{
		"domain":  domain,
		"user_id": userID,
		"email":   user.Email,
	}).Debug("ValidateSession: access granted")

	groupIDs, groupNames := pairGroupIDsAndNames(userGroups)
	return &proto.ValidateSessionResponse{
		Valid:          true,
		UserId:         user.Id,
		UserEmail:      user.Email,
		PeerGroupIds:   groupIDs,
		PeerGroupNames: groupNames,
	}, nil
}

func (s *ProxyServiceServer) getServiceByDomain(ctx context.Context, domain string) (*rpservice.Service, error) {
	return s.serviceManager.GetServiceByDomain(ctx, domain)
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

// ValidateTunnelPeer resolves an inbound peer by its WireGuard tunnel IP and
// checks the peer's group membership against the service's access groups.
// Peers without a user (machine agents, automation workloads) are first-class
// callers; authorisation runs off peer-group memberships rather than the
// optional owning user's auto-groups. On success a session JWT is minted so
// the proxy can install a cookie and skip subsequent management round-trips.
func (s *ProxyServiceServer) ValidateTunnelPeer(ctx context.Context, req *proto.ValidateTunnelPeerRequest) (*proto.ValidateTunnelPeerResponse, error) {
	domain := req.GetDomain()
	tunnelIPStr := req.GetTunnelIp()

	if domain == "" || tunnelIPStr == "" {
		return &proto.ValidateTunnelPeerResponse{
			Valid:        false,
			DeniedReason: "missing domain or tunnel_ip",
		}, nil
	}

	tunnelIP := net.ParseIP(tunnelIPStr)
	if tunnelIP == nil {
		return &proto.ValidateTunnelPeerResponse{
			Valid:        false,
			DeniedReason: "invalid_tunnel_ip",
		}, nil
	}

	service, err := s.getServiceByDomain(ctx, domain)
	if err != nil {
		log.WithFields(log.Fields{"domain": domain, "error": err.Error()}).Debug("ValidateTunnelPeer: service not found")
		//nolint:nilerr
		return &proto.ValidateTunnelPeerResponse{
			Valid:        false,
			DeniedReason: "service_not_found",
		}, nil
	}

	// Mirror ValidateSession: account-scoped (BYOP) proxy tokens may only
	// validate and mint session cookies for their own account's domains.
	if err := enforceAccountScope(ctx, service.AccountID); err != nil {
		return nil, err
	}

	peer, err := s.peersManager.GetPeerByTunnelIP(ctx, service.AccountID, tunnelIP)
	if err != nil || peer == nil {
		log.WithFields(log.Fields{"domain": domain, "tunnel_ip": tunnelIPStr}).Debug("ValidateTunnelPeer: peer not found")
		//nolint:nilerr
		return &proto.ValidateTunnelPeerResponse{
			Valid:        false,
			DeniedReason: "peer_not_found",
		}, nil
	}

	_, peerGroups, err := s.peersManager.GetPeerWithGroups(ctx, service.AccountID, peer.ID)
	if err != nil {
		log.WithFields(log.Fields{"domain": domain, "peer_id": peer.ID, "error": err.Error()}).Debug("ValidateTunnelPeer: peer groups lookup failed")
		//nolint:nilerr
		return &proto.ValidateTunnelPeerResponse{
			Valid:        false,
			DeniedReason: "peer_not_found",
		}, nil
	}

	groupIDs, groupNames := pairGroupIDsAndNames(peerGroups)
	principalID, displayIdentity := s.getTunnelPeerInfo(ctx, domain, service, peer)

	if err := checkPeerGroupAccess(service, groupIDs); err != nil {
		log.WithFields(log.Fields{"domain": domain, "peer_id": peer.ID, "error": err.Error()}).Debug("ValidateTunnelPeer: access denied")
		//nolint:nilerr
		return &proto.ValidateTunnelPeerResponse{
			Valid:          false,
			UserId:         principalID,
			UserEmail:      displayIdentity,
			DeniedReason:   "not_in_group",
			PeerGroupIds:   groupIDs,
			PeerGroupNames: groupNames,
		}, nil
	}

	token, err := s.generateSessionToken(ctx, true, service, principalID, displayIdentity, proxyauth.MethodOIDC, groupIDs, groupNames)
	if err != nil {
		return nil, err
	}

	log.WithFields(log.Fields{
		"domain":       domain,
		"tunnel_ip":    tunnelIPStr,
		"peer_id":      peer.ID,
		"principal_id": principalID,
	}).Debug("ValidateTunnelPeer: access granted")

	return &proto.ValidateTunnelPeerResponse{
		Valid:          true,
		UserId:         principalID,
		UserEmail:      displayIdentity,
		SessionToken:   token,
		PeerGroupIds:   groupIDs,
		PeerGroupNames: groupNames,
	}, nil
}

// getTunnelPeerInfo returns the principal ID and display name for a peer, e.g. a
// user or peer ID, and peer name or user email.
func (s *ProxyServiceServer) getTunnelPeerInfo(ctx context.Context, domain string, service *rpservice.Service, peer *peer.Peer) (string, string) {
	// Resolve the principal: when the peer is linked to a user, the human is the
	// principal so multiple peers owned by the same user share a single
	// identity. Unlinked peers (machine agents) are their own principal keyed on
	// peer.ID. displayIdentity is what upstream gateways tag spend with —
	// user.Email when linked, peer.Name when not.

	// If the peer isn't associated with a user, return the peer info directly.
	if peer.UserID == "" {
		return peer.ID, peer.Name
	}

	// Otherwise, if the peer is linked to a user, the user is the principal and
	// if an IdP is available, we gather details on the user from it.
	principalID := peer.UserID
	displayIdentity := peer.Name
	// Stored column first (cheap, but often empty for OIDC-provisioned users).
	if user, uerr := s.usersManager.GetUser(ctx, peer.UserID); uerr == nil && user != nil {
		principalID = user.Id
		if user.Email != "" {
			displayIdentity = user.Email
		}
	}
	// IdP enrichment wins when available — the stored email column is a
	// best-effort cache and is frequently empty for OIDC users. Enrichment
	// failures must never fail the RPC; we simply keep the stored/peer identity.
	if s.idpManager != nil {
		if ud, uerr := s.idpManager.GetUserDataByID(ctx, peer.UserID, idp.AppMetadata{WTAccountID: service.AccountID}); uerr == nil && ud != nil && ud.Email != "" {
			displayIdentity = ud.Email
		} else if uerr != nil {
			log.WithFields(log.Fields{"domain": domain, "user_id": peer.UserID, "error": uerr.Error()}).Debug("ValidateTunnelPeer: IdP user enrichment failed; using stored/peer identity")
		}
	}

	return principalID, displayIdentity
}

// checkPeerGroupAccess gates ValidateTunnelPeer by the service's required
// groups. Private services authorise against AccessGroups (empty list fails
// closed — Validate() rejects that at save time but the RPC is the security
// boundary and must not trust upstream state). Bearer-auth services authorise
// against DistributionGroups when populated. Non-private non-bearer services
// are open.
func checkPeerGroupAccess(service *rpservice.Service, peerGroupIDs []string) error {
	if service.Private {
		if len(service.AccessGroups) == 0 {
			return fmt.Errorf("private service has no access groups")
		}
		return matchAnyGroup(service.AccessGroups, peerGroupIDs)
	}
	if service.Auth.BearerAuth != nil && service.Auth.BearerAuth.Enabled && len(service.Auth.BearerAuth.DistributionGroups) > 0 {
		return matchAnyGroup(service.Auth.BearerAuth.DistributionGroups, peerGroupIDs)
	}
	return nil
}

// matchAnyGroup returns nil when peerGroupIDs intersects allowedGroups,
// else a non-nil error.
func matchAnyGroup(allowedGroups, peerGroupIDs []string) error {
	if len(allowedGroups) == 0 {
		return fmt.Errorf("no allowed groups configured")
	}
	allowed := make(map[string]struct{}, len(allowedGroups))
	for _, g := range allowedGroups {
		allowed[g] = struct{}{}
	}
	for _, g := range peerGroupIDs {
		if _, ok := allowed[g]; ok {
			return nil
		}
	}
	return fmt.Errorf("peer not in allowed groups")
}
