package grpc

// Machine Tunnel Fork - gRPC handlers for machine peer registration and sync.
// These handlers require mTLS authentication and use the MTLSIdentity from context.

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/netbirdio/netbird/management/internals/shared/mtls"
	nbContext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// RegisterMachinePeer handles machine peer registration using mTLS certificate authentication.
// This method is in mTLSRequiredMethods and will only be called with valid mTLS identity.
func (s *Server) RegisterMachinePeer(ctx context.Context, req *proto.MachineRegisterRequest) (*proto.MachineRegisterResponse, error) {
	reqStart := time.Now()

	// Extract mTLS identity from context (set by MTLSUnaryInterceptor)
	identity := mtls.GetIdentity(ctx)
	if identity == nil {
		// This should not happen - interceptor should reject requests without identity
		log.WithContext(ctx).Error("RegisterMachinePeer called without mTLS identity")
		return nil, status.Error(codes.Unauthenticated, "mTLS authentication required")
	}

	log.WithContext(ctx).Infof("RegisterMachinePeer: DNS=%s, Account=%s, Hostname=%s",
		identity.DNSName, identity.AccountID, identity.Hostname)

	// Parse WireGuard public key from request
	if len(req.GetWgPubKey()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "WireGuard public key is required")
	}
	peerKey, err := wgtypes.ParseKey(string(req.GetWgPubKey()))
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid WireGuard public key: %v", err)
	}

	// Add peer and account info to context for logging
	//nolint:staticcheck
	ctx = context.WithValue(ctx, nbContext.PeerIDKey, peerKey.String())

	// Get account ID from mTLS identity
	// The AccountID is set by extractMTLSIdentity based on domain-account mapping
	accountID := identity.AccountID
	if accountID == "" {
		log.WithContext(ctx).Errorf("No account ID in mTLS identity for domain %s", identity.Domain)
		return nil, status.Errorf(codes.FailedPrecondition,
			"domain %q not mapped to any account - configure MTLSDomainAccountMapping", identity.Domain)
	}
	//nolint:staticcheck
	ctx = context.WithValue(ctx, nbContext.AccountIDKey, accountID)

	// Build peer metadata from request
	peerMeta := extractPeerMeta(ctx, req.GetMeta())

	// Log registration attempt (truncate keys for security)
	keyPrefix := peerKey.String()
	if len(keyPrefix) > 8 {
		keyPrefix = keyPrefix[:8]
	}
	accountPrefix := accountID
	if len(accountPrefix) > 8 {
		accountPrefix = accountPrefix[:8]
	}
	log.WithContext(ctx).Infof("Machine peer registration: key=%s... hostname=%s domain=%s account=%s...",
		keyPrefix, identity.Hostname, identity.Domain, accountPrefix)

	// Register or update the machine peer
	peer, netMap, postureChecks, err := s.accountManager.LoginPeer(ctx, types.PeerLogin{
		WireGuardPubKey: peerKey.String(),
		Meta:            peerMeta,
		// Machine peer specific: no setup key, no user ID (auth via mTLS)
		SetupKey: "",
		UserID:   "",
	})
	if err != nil {
		log.WithContext(ctx).Errorf("Failed to register machine peer: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to register peer: %v", err)
	}

	// Build response with machine-specific configuration
	loginResp, err := s.prepareLoginResponse(ctx, peer, netMap, postureChecks)
	if err != nil {
		log.WithContext(ctx).Errorf("Failed to prepare login response: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to prepare response: %v", err)
	}

	// Convert LoginResponse to MachineRegisterResponse
	response := &proto.MachineRegisterResponse{
		PeerConfig:    loginResp.GetPeerConfig(),
		NetbirdConfig: loginResp.GetNetbirdConfig(),
		MachineIdentity: &proto.MachineIdentity{
			DnsName:           identity.DNSName,
			Hostname:          identity.Hostname,
			Domain:            identity.Domain,
			IssuerFingerprint: identity.IssuerFingerprint,
			SerialNumber:      identity.SerialNumber,
			TemplateOid:       identity.TemplateOID,
		},
		// TODO: Filter routes to only DC routes based on ACLs
		AllowedDcRoutes: nil, // Will be populated in T-3.6b
		DnsConfig:       nil, // Will be populated based on DC DNS config
	}

	log.WithContext(ctx).Infof("Machine peer registered successfully: DNS=%s, IP=%s (took %s)",
		identity.DNSName, peer.IP, time.Since(reqStart))

	return response, nil
}

// SyncMachinePeer handles machine peer sync stream using mTLS certificate authentication.
func (s *Server) SyncMachinePeer(req *proto.MachineSyncRequest, srv proto.ManagementService_SyncMachinePeerServer) error {
	ctx := srv.Context()

	// Extract mTLS identity from context
	identity := mtls.GetIdentity(ctx)
	if identity == nil {
		log.WithContext(ctx).Error("SyncMachinePeer called without mTLS identity")
		return status.Error(codes.Unauthenticated, "mTLS authentication required")
	}

	log.WithContext(ctx).Infof("SyncMachinePeer: DNS=%s", identity.DNSName)

	// TODO: Implement sync stream similar to Sync but for machine peers
	// This should:
	// 1. Look up peer by mTLS identity (hostname + domain)
	// 2. Stream network map updates to the machine peer
	// 3. Handle DC route changes

	return status.Error(codes.Unimplemented, "SyncMachinePeer not yet implemented")
}

// GetMachineRoutes returns the DC routes allowed for a machine peer.
func (s *Server) GetMachineRoutes(ctx context.Context, req *proto.MachineRoutesRequest) (*proto.MachineRoutesResponse, error) {
	// Extract mTLS identity from context
	identity := mtls.GetIdentity(ctx)
	if identity == nil {
		return nil, status.Error(codes.Unauthenticated, "mTLS authentication required")
	}

	log.WithContext(ctx).Infof("GetMachineRoutes: DNS=%s, IncludeOffline=%v",
		identity.DNSName, req.GetIncludeOffline())

	// TODO: Implement route retrieval based on peer and account ACLs
	return nil, status.Error(codes.Unimplemented, "GetMachineRoutes not yet implemented")
}

// ReportMachineStatus handles machine peer status reports.
func (s *Server) ReportMachineStatus(ctx context.Context, req *proto.MachineStatusRequest) (*proto.MachineStatusResponse, error) {
	// Extract mTLS identity from context
	identity := mtls.GetIdentity(ctx)
	if identity == nil {
		return nil, status.Error(codes.Unauthenticated, "mTLS authentication required")
	}

	log.WithContext(ctx).Debugf("ReportMachineStatus: DNS=%s, TunnelUp=%v, DCReachable=%v",
		identity.DNSName, req.GetTunnelUp(), req.GetDcReachable())

	// TODO: Store status for monitoring/alerting
	// This could update peer.LastSeen and store tunnel metrics

	return &proto.MachineStatusResponse{
		Ack:        true,
		ServerTime: timestamppb.Now(),
	}, nil
}
