package grpc

import (
	"context"
	"slices"
	"time"

	pb "github.com/golang/protobuf/proto" // nolint
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/encryption"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy"
	"github.com/netbirdio/netbird/management/server/activity"
	nbContext "github.com/netbirdio/netbird/management/server/context"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/proto"
	internalStatus "github.com/netbirdio/netbird/shared/management/status"
)

const (
	exposeTTL          = 90 * time.Second
	exposeReapInterval = 30 * time.Second
)

type activeExpose struct {
	serviceID   string
	domain      string
	accountID   string
	peerID      string
	peerUserID  string
	serviceMeta map[string]any
	lastRenewed time.Time
}

func exposeKey(peerID, domain string) string {
	return peerID + ":" + domain
}

// CreateExpose handles a peer request to create a new expose service.
func (s *Server) CreateExpose(ctx context.Context, req *proto.EncryptedMessage) (*proto.EncryptedMessage, error) {
	exposeReq := &proto.ExposeServiceRequest{}
	peerKey, err := s.parseRequest(ctx, req, exposeReq)
	if err != nil {
		return nil, err
	}

	accountID, peer, err := s.authenticateExposePeer(ctx, peerKey)
	if err != nil {
		return nil, err
	}

	// nolint:staticcheck
	ctx = context.WithValue(ctx, nbContext.AccountIDKey, accountID)

	if exposeReq.Protocol != proto.ExposeProtocol_EXPOSE_HTTP {
		return nil, status.Errorf(codes.InvalidArgument, "only HTTP protocol is supported")
	}

	if err := s.validateExposePermission(ctx, accountID, peer.ID); err != nil {
		return nil, err
	}

	serviceName, err := reverseproxy.GenerateExposeName(exposeReq.NamePrefix)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "generate service name: %v", err)
	}

	service, err := s.createExposeService(ctx, accountID, peer, exposeReq, serviceName)
	if err != nil {
		return nil, err
	}

	key := exposeKey(peer.ID, service.Domain)
	if _, loaded := s.activeExposes.LoadOrStore(key, &activeExpose{
		serviceID:   service.ID,
		domain:      service.Domain,
		accountID:   accountID,
		peerID:      peer.ID,
		peerUserID:  peer.UserID,
		serviceMeta: service.EventMeta(),
		lastRenewed: time.Now(),
	}); loaded {
		s.deleteExposeService(ctx, accountID, peer.ID, service)
		return nil, status.Errorf(codes.AlreadyExists, "peer already has an active expose session for this domain")
	}

	s.accountManager.StoreEvent(ctx, peer.UserID, service.ID, accountID,
		activity.PeerServiceExposed, service.EventMeta())

	resp := &proto.ExposeServiceResponse{
		ServiceName: service.Name,
		ServiceUrl:  "https://" + service.Domain,
		Domain:      service.Domain,
	}

	return s.encryptResponse(peerKey, resp)
}

// RenewExpose extends the TTL of an active expose session.
func (s *Server) RenewExpose(ctx context.Context, req *proto.EncryptedMessage) (*proto.EncryptedMessage, error) {
	renewReq := &proto.RenewExposeRequest{}
	peerKey, err := s.parseRequest(ctx, req, renewReq)
	if err != nil {
		return nil, err
	}

	_, peer, err := s.authenticateExposePeer(ctx, peerKey)
	if err != nil {
		return nil, err
	}

	key := exposeKey(peer.ID, renewReq.Domain)
	val, ok := s.activeExposes.Load(key)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "no active expose session for domain %s", renewReq.Domain)
	}

	expose := val.(*activeExpose)
	expose.lastRenewed = time.Now()

	return s.encryptResponse(peerKey, &proto.RenewExposeResponse{})
}

// StopExpose terminates an active expose session.
func (s *Server) StopExpose(ctx context.Context, req *proto.EncryptedMessage) (*proto.EncryptedMessage, error) {
	stopReq := &proto.StopExposeRequest{}
	peerKey, err := s.parseRequest(ctx, req, stopReq)
	if err != nil {
		return nil, err
	}

	_, peer, err := s.authenticateExposePeer(ctx, peerKey)
	if err != nil {
		return nil, err
	}

	key := exposeKey(peer.ID, stopReq.Domain)
	val, ok := s.activeExposes.LoadAndDelete(key)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "no active expose session for domain %s", stopReq.Domain)
	}

	expose := val.(*activeExpose)
	s.cleanupExpose(expose)

	return s.encryptResponse(peerKey, &proto.StopExposeResponse{})
}

// StartExposeReaper starts a background goroutine that reaps expired expose sessions.
func (s *Server) StartExposeReaper(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(exposeReapInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.reapExpiredExposes()
			}
		}
	}()
}

func (s *Server) reapExpiredExposes() {
	s.activeExposes.Range(func(key, val any) bool {
		expose := val.(*activeExpose)
		if time.Since(expose.lastRenewed) > exposeTTL {
			if _, deleted := s.activeExposes.LoadAndDelete(key); deleted {
				log.Infof("reaping expired expose session for peer %s, domain %s", expose.peerID, expose.domain)
				s.cleanupExpose(expose)
			}
		}
		return true
	})
}

func (s *Server) encryptResponse(peerKey wgtypes.Key, msg pb.Message) (*proto.EncryptedMessage, error) {
	wgKey, err := s.secretsManager.GetWGKey()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "internal error")
	}

	encryptedResp, err := encryption.EncryptMessage(peerKey, wgKey, msg)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "encrypt response")
	}

	return &proto.EncryptedMessage{
		WgPubKey: wgKey.PublicKey().String(),
		Body:     encryptedResp,
	}, nil
}

func (s *Server) authenticateExposePeer(ctx context.Context, peerKey wgtypes.Key) (string, *nbpeer.Peer, error) {
	accountID, err := s.accountManager.GetAccountIDForPeerKey(ctx, peerKey.String())
	if err != nil {
		if errStatus, ok := internalStatus.FromError(err); ok && errStatus.Type() == internalStatus.NotFound {
			return "", nil, status.Errorf(codes.PermissionDenied, "peer is not registered")
		}
		return "", nil, err
	}

	peer, err := s.accountManager.GetStore().GetPeerByPeerPubKey(ctx, store.LockingStrengthNone, peerKey.String())
	if err != nil {
		return "", nil, status.Errorf(codes.Unauthenticated, "peer is not registered")
	}

	return accountID, peer, nil
}

func (s *Server) validateExposePermission(ctx context.Context, accountID, peerID string) error {
	settings, err := s.settingsManager.GetExtraSettings(ctx, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get extra settings: %v", err)
		return status.Errorf(codes.Internal, "get account settings")
	}

	if settings == nil || !settings.PeerExposeEnabled {
		return status.Errorf(codes.PermissionDenied, "peer expose is not enabled for this account")
	}

	if len(settings.PeerExposeGroups) > 0 {
		peerGroupIDs, err := s.accountManager.GetStore().GetPeerGroupIDs(ctx, store.LockingStrengthNone, accountID, peerID)
		if err != nil {
			log.WithContext(ctx).Errorf("failed to get peer group IDs: %v", err)
			return status.Errorf(codes.Internal, "get peer groups")
		}

		allowed := false
		for _, pg := range peerGroupIDs {
			if slices.Contains(settings.PeerExposeGroups, pg) {
				allowed = true
				break
			}
		}
		if !allowed {
			return status.Errorf(codes.PermissionDenied, "peer is not in an allowed expose group")
		}
	}

	return nil
}

func (s *Server) createExposeService(ctx context.Context, accountID string, peer *nbpeer.Peer, req *proto.ExposeServiceRequest, serviceName string) (*reverseproxy.Service, error) {
	service := &reverseproxy.Service{
		AccountID: accountID,
		Name:      serviceName,
		Enabled:   true,
		Targets: []*reverseproxy.Target{
			{
				AccountID:  accountID,
				Port:       int(req.Port),
				Protocol:   "http",
				TargetId:   peer.ID,
				TargetType: reverseproxy.TargetTypePeer,
				Enabled:    true,
			},
		},
	}

	if req.Domain != "" {
		service.Domain = service.Name + "." + req.Domain
	}

	if req.Pin != "" {
		service.Auth.PinAuth = &reverseproxy.PINAuthConfig{
			Enabled: true,
			Pin:     req.Pin,
		}
	}

	if req.Password != "" {
		service.Auth.PasswordAuth = &reverseproxy.PasswordAuthConfig{
			Enabled:  true,
			Password: req.Password,
		}
	}

	if len(req.UserGroups) > 0 {
		service.Auth.BearerAuth = &reverseproxy.BearerAuthConfig{
			Enabled:            true,
			DistributionGroups: req.UserGroups,
		}
	}

	reverseProxyMgr := s.getReverseProxyManager()
	if reverseProxyMgr == nil {
		return nil, status.Errorf(codes.Internal, "reverse proxy manager not available")
	}

	created, err := reverseProxyMgr.CreateServiceFromPeer(ctx, accountID, peer.ID, service)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to create service from peer: %v", err)
		return nil, status.Errorf(codes.Internal, "create service: %v", err)
	}

	return created, nil
}

func (s *Server) deleteExposeService(ctx context.Context, accountID, peerID string, service *reverseproxy.Service) {
	reverseProxyMgr := s.getReverseProxyManager()
	if reverseProxyMgr == nil {
		return
	}
	if err := reverseProxyMgr.DeleteServiceFromPeer(ctx, accountID, peerID, service.ID); err != nil {
		log.WithContext(ctx).Debugf("failed to delete expose service %s: %v", service.ID, err)
	}
}

func (s *Server) cleanupExpose(expose *activeExpose) {
	bgCtx := context.Background()

	reverseProxyMgr := s.getReverseProxyManager()
	if reverseProxyMgr == nil {
		log.Errorf("cannot cleanup exposed service %s: reverse proxy manager not available", expose.serviceID)
		return
	}

	if err := reverseProxyMgr.DeleteServiceFromPeer(bgCtx, expose.accountID, expose.peerID, expose.serviceID); err != nil {
		log.Errorf("failed to delete peer-exposed service %s: %v", expose.serviceID, err)
	}

	s.accountManager.StoreEvent(bgCtx, expose.peerUserID, expose.serviceID, expose.accountID,
		activity.PeerServiceUnexposed, expose.serviceMeta)
}

func (s *Server) getReverseProxyManager() reverseproxy.Manager {
	s.reverseProxyMu.RLock()
	defer s.reverseProxyMu.RUnlock()
	return s.reverseProxyManager
}

// SetReverseProxyManager sets the reverse proxy manager on the server.
func (s *Server) SetReverseProxyManager(mgr reverseproxy.Manager) {
	s.reverseProxyMu.Lock()
	defer s.reverseProxyMu.Unlock()
	s.reverseProxyManager = mgr
}
