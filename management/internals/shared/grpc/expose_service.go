package grpc

import (
	"context"
	"fmt"

	pb "github.com/golang/protobuf/proto" // nolint
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/encryption"
	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	nbContext "github.com/netbirdio/netbird/management/server/context"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/proto"
	internalStatus "github.com/netbirdio/netbird/shared/management/status"
)

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

	reverseProxyMgr := s.getReverseProxyManager()
	if reverseProxyMgr == nil {
		return nil, status.Errorf(codes.Internal, "reverse proxy manager not available")
	}

	if exposeReq.Port > 65535 {
		return nil, status.Errorf(codes.InvalidArgument, "port out of range: %d", exposeReq.Port)
	}
	if exposeReq.ListenPort > 65535 {
		return nil, status.Errorf(codes.InvalidArgument, "listen_port out of range: %d", exposeReq.ListenPort)
	}

	mode, err := exposeProtocolToString(exposeReq.Protocol)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	created, err := reverseProxyMgr.CreateServiceFromPeer(ctx, accountID, peer.ID, &rpservice.ExposeServiceRequest{
		NamePrefix:     exposeReq.NamePrefix,
		Port:           uint16(exposeReq.Port), //nolint:gosec // validated above
		Mode:           mode,
		TargetProtocol: exposeTargetProtocol(exposeReq.Protocol),
		Domain:         exposeReq.Domain,
		Pin:            exposeReq.Pin,
		Password:       exposeReq.Password,
		UserGroups:     exposeReq.UserGroups,
		ListenPort:     uint16(exposeReq.ListenPort), //nolint:gosec // validated above
	})
	if err != nil {
		return nil, mapExposeError(ctx, err)
	}

	return s.encryptResponse(peerKey, &proto.ExposeServiceResponse{
		ServiceName:      created.ServiceName,
		ServiceUrl:       created.ServiceURL,
		Domain:           created.Domain,
		PortAutoAssigned: created.PortAutoAssigned,
	})
}

// RenewExpose extends the TTL of an active expose session.
func (s *Server) RenewExpose(ctx context.Context, req *proto.EncryptedMessage) (*proto.EncryptedMessage, error) {
	renewReq := &proto.RenewExposeRequest{}
	peerKey, err := s.parseRequest(ctx, req, renewReq)
	if err != nil {
		return nil, err
	}

	accountID, peer, err := s.authenticateExposePeer(ctx, peerKey)
	if err != nil {
		return nil, err
	}

	reverseProxyMgr := s.getReverseProxyManager()
	if reverseProxyMgr == nil {
		return nil, status.Errorf(codes.Internal, "reverse proxy manager not available")
	}

	serviceID, err := s.resolveServiceID(ctx, renewReq.Domain)
	if err != nil {
		return nil, mapExposeError(ctx, err)
	}

	if err := reverseProxyMgr.RenewServiceFromPeer(ctx, accountID, peer.ID, serviceID); err != nil {
		return nil, mapExposeError(ctx, err)
	}

	return s.encryptResponse(peerKey, &proto.RenewExposeResponse{})
}

// StopExpose terminates an active expose session.
func (s *Server) StopExpose(ctx context.Context, req *proto.EncryptedMessage) (*proto.EncryptedMessage, error) {
	stopReq := &proto.StopExposeRequest{}
	peerKey, err := s.parseRequest(ctx, req, stopReq)
	if err != nil {
		return nil, err
	}

	accountID, peer, err := s.authenticateExposePeer(ctx, peerKey)
	if err != nil {
		return nil, err
	}

	reverseProxyMgr := s.getReverseProxyManager()
	if reverseProxyMgr == nil {
		return nil, status.Errorf(codes.Internal, "reverse proxy manager not available")
	}

	serviceID, err := s.resolveServiceID(ctx, stopReq.Domain)
	if err != nil {
		return nil, mapExposeError(ctx, err)
	}

	if err := reverseProxyMgr.StopServiceFromPeer(ctx, accountID, peer.ID, serviceID); err != nil {
		return nil, mapExposeError(ctx, err)
	}

	return s.encryptResponse(peerKey, &proto.StopExposeResponse{})
}

func mapExposeError(ctx context.Context, err error) error {
	s, ok := internalStatus.FromError(err)
	if !ok {
		log.WithContext(ctx).Errorf("expose service error: %v", err)
		return status.Errorf(codes.Internal, "internal error")
	}

	switch s.Type() {
	case internalStatus.InvalidArgument:
		return status.Errorf(codes.InvalidArgument, "%s", s.Message)
	case internalStatus.PermissionDenied:
		return status.Errorf(codes.PermissionDenied, "%s", s.Message)
	case internalStatus.NotFound:
		return status.Errorf(codes.NotFound, "%s", s.Message)
	case internalStatus.AlreadyExists:
		return status.Errorf(codes.AlreadyExists, "%s", s.Message)
	case internalStatus.PreconditionFailed:
		return status.Errorf(codes.ResourceExhausted, "%s", s.Message)
	default:
		log.WithContext(ctx).Errorf("expose service error: %v", err)
		return status.Errorf(codes.Internal, "internal error")
	}
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
		return "", nil, status.Errorf(codes.Internal, "lookup account for peer")
	}

	peer, err := s.accountManager.GetStore().GetPeerByPeerPubKey(ctx, store.LockingStrengthNone, peerKey.String())
	if err != nil {
		return "", nil, status.Errorf(codes.PermissionDenied, "peer is not registered")
	}

	return accountID, peer, nil
}

func (s *Server) getReverseProxyManager() rpservice.Manager {
	s.reverseProxyMu.RLock()
	defer s.reverseProxyMu.RUnlock()
	return s.reverseProxyManager
}

// SetReverseProxyManager sets the reverse proxy manager on the server.
func (s *Server) SetReverseProxyManager(mgr rpservice.Manager) {
	s.reverseProxyMu.Lock()
	defer s.reverseProxyMu.Unlock()
	s.reverseProxyManager = mgr
}

// resolveServiceID looks up the service by its globally unique domain.
func (s *Server) resolveServiceID(ctx context.Context, domain string) (string, error) {
	if domain == "" {
		return "", status.Errorf(codes.InvalidArgument, "domain is required")
	}

	svc, err := s.accountManager.GetStore().GetServiceByDomain(ctx, domain)
	if err != nil {
		return "", err
	}
	return svc.ID, nil
}

func exposeProtocolToString(p proto.ExposeProtocol) (string, error) {
	switch p {
	case proto.ExposeProtocol_EXPOSE_HTTP, proto.ExposeProtocol_EXPOSE_HTTPS:
		return "http", nil
	case proto.ExposeProtocol_EXPOSE_TCP:
		return "tcp", nil
	case proto.ExposeProtocol_EXPOSE_UDP:
		return "udp", nil
	case proto.ExposeProtocol_EXPOSE_TLS:
		return "tls", nil
	default:
		return "", fmt.Errorf("unsupported expose protocol: %v", p)
	}
}

// exposeTargetProtocol returns the target protocol for the given expose protocol.
// For HTTP mode, this is http or https (the scheme used to connect to the backend).
// For L4 modes, this is tcp or udp (the transport used to connect to the backend).
func exposeTargetProtocol(p proto.ExposeProtocol) string {
	switch p {
	case proto.ExposeProtocol_EXPOSE_HTTPS:
		return rpservice.TargetProtoHTTPS
	case proto.ExposeProtocol_EXPOSE_TCP, proto.ExposeProtocol_EXPOSE_TLS:
		return rpservice.TargetProtoTCP
	case proto.ExposeProtocol_EXPOSE_UDP:
		return rpservice.TargetProtoUDP
	default:
		return rpservice.TargetProtoHTTP
	}
}
