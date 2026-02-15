package grpc

import (
	"context"
	"errors"
	"io"
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

const exposeKeepAliveInterval = 30 * time.Second

// ExposeService handles a peer-initiated service expose stream.
func (s *Server) ExposeService(srv proto.ManagementService_ExposeServiceServer) error {
	ctx := srv.Context()

	peerKey, exposeReq, err := s.receiveExposeHandshake(ctx, srv)
	if err != nil {
		return err
	}

	accountID, peer, err := s.authenticateExposePeer(ctx, peerKey)
	if err != nil {
		return err
	}

	// nolint:staticcheck
	ctx = context.WithValue(ctx, nbContext.AccountIDKey, accountID)

	if exposeReq.Protocol != proto.ExposeProtocol_EXPOSE_HTTP {
		return status.Errorf(codes.InvalidArgument, "only HTTP protocol is supported")
	}

	if err := s.validateExposePermission(ctx, accountID, peer.ID); err != nil {
		return err
	}

	if _, loaded := s.activeExposes.LoadOrStore(peer.ID, ""); loaded {
		return status.Errorf(codes.AlreadyExists, "peer already has an active expose session")
	}
	defer s.activeExposes.Delete(peer.ID)

	serviceName, err := reverseproxy.GenerateExposeName(exposeReq.NamePrefix)
	if err != nil {
		return status.Errorf(codes.Internal, "generate service name: %v", err)
	}

	service, err := s.createExposeService(ctx, accountID, peer, exposeReq, serviceName)
	if err != nil {
		return err
	}

	s.activeExposes.Store(peer.ID, service.ID)

	defer s.cleanupExposedService(accountID, peer, service)

	s.accountManager.StoreEvent(ctx, peer.UserID, service.ID, accountID,
		activity.PeerServiceExposed, service.EventMeta())

	if err := s.sendExposeResponse(ctx, peerKey, srv, service); err != nil {
		return err
	}

	return s.exposeKeepAliveLoop(ctx, peerKey, srv)
}

func (s *Server) receiveExposeHandshake(ctx context.Context, srv proto.ManagementService_ExposeServiceServer) (wgtypes.Key, *proto.ExposeServiceRequest, error) {
	hello, err := srv.Recv()
	if err != nil {
		return wgtypes.Key{}, nil, status.Errorf(codes.InvalidArgument, "missing handshake: %v", err)
	}

	exposeReq := &proto.ExposeServiceRequest{}
	peerKey, err := s.parseRequest(ctx, hello, exposeReq)
	if err != nil {
		return wgtypes.Key{}, nil, err
	}

	return peerKey, exposeReq, nil
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

func (s *Server) sendExposeResponse(ctx context.Context, peerKey wgtypes.Key, srv proto.ManagementService_ExposeServiceServer, service *reverseproxy.Service) error {
	resp := &proto.ExposeServiceResponse{
		ServiceId:   service.ID,
		ServiceName: service.Name,
		ServiceUrl:  "https://" + service.Domain,
		Domain:      service.Domain,
	}

	return s.sendEncryptedMessage(ctx, peerKey, srv, resp)
}

func (s *Server) sendEncryptedMessage(ctx context.Context, peerKey wgtypes.Key, srv proto.ManagementService_ExposeServiceServer, msg pb.Message) error {
	wgKey, err := s.secretsManager.GetWGKey()
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get wg key: %v", err)
		return status.Errorf(codes.Internal, "internal error")
	}

	encryptedResp, err := encryption.EncryptMessage(peerKey, wgKey, msg)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to encrypt response: %v", err)
		return status.Errorf(codes.Internal, "encrypt response")
	}

	return srv.Send(&proto.EncryptedMessage{
		WgPubKey: wgKey.PublicKey().String(),
		Body:     encryptedResp,
	})
}

func (s *Server) exposeKeepAliveLoop(ctx context.Context, peerKey wgtypes.Key, srv proto.ManagementService_ExposeServiceServer) error {
	ticker := time.NewTicker(exposeKeepAliveInterval)
	defer ticker.Stop()

	recvErr := make(chan error, 1)
	go func() {
		for {
			_, err := srv.Recv()
			if err != nil {
				recvErr <- err
				return
			}
		}
	}()

	keepAlive := &proto.ExposeServiceKeepAlive{}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-recvErr:
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		case <-ticker.C:
			if err := s.sendEncryptedMessage(ctx, peerKey, srv, keepAlive); err != nil {
				log.WithContext(ctx).Debugf("failed to send keep-alive: %v", err)
				return err
			}
		}
	}
}

func (s *Server) cleanupExposedService(accountID string, peer *nbpeer.Peer, service *reverseproxy.Service) {
	bgCtx := context.Background()

	reverseProxyMgr := s.getReverseProxyManager()
	if reverseProxyMgr == nil {
		log.Errorf("cannot cleanup exposed service %s: reverse proxy manager not available", service.ID)
		return
	}

	if err := reverseProxyMgr.DeleteServiceFromPeer(bgCtx, accountID, peer.ID, service.ID); err != nil {
		log.Errorf("failed to delete peer-exposed service %s: %v", service.ID, err)
	}

	s.accountManager.StoreEvent(bgCtx, peer.UserID, service.ID, accountID,
		activity.PeerServiceUnexposed, service.EventMeta())
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
