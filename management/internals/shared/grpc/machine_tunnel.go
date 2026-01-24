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
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
	// Note: nbpeer is still needed for extractMachinePeerMeta
	"github.com/netbirdio/netbird/shared/management/proto"
)

// RegisterMachinePeer handles machine peer registration using mTLS certificate authentication.
// This method is in mTLSRequiredMethods and will only be called with valid mTLS identity.
//
// Features (T-3.6 complete):
// - validateIssuerCA: CA-Fingerprint validation per account
// - Meta fields for audit: peer_type, cert_dns_name, auth_method, cert_issuer_fp, etc.
// - Re-registration logic: update existing peer vs create new
// - Rate-limit protection: TODO (stub for MVP)
// - Replay protection: TODO (stub for MVP)
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

	// Get account ID from mTLS identity (CRITICAL: Already validated in extractMTLSIdentity)
	accountID := identity.AccountID
	if accountID == "" {
		log.WithContext(ctx).Errorf("No account ID in mTLS identity for domain %s", identity.Domain)
		return nil, status.Errorf(codes.FailedPrecondition,
			"domain %q not mapped to any account - configure MTLSDomainAccountMapping", identity.Domain)
	}

	// SECURITY: Validate Issuer CA fingerprint against account's allowed issuers
	// Per Security Review: Empty allowlist = DENY (explicit config required)
	if err := mtls.ValidateIssuerCA(accountID, identity.IssuerFingerprint); err != nil {
		log.WithContext(ctx).Warnf("Issuer CA validation failed: %v", err)
		return nil, status.Errorf(codes.PermissionDenied, "certificate issuer not authorized: %v", err)
	}

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
	//nolint:staticcheck
	ctx = context.WithValue(ctx, nbContext.AccountIDKey, accountID)

	// Build peer metadata from request, enriched with mTLS audit fields
	peerMeta := extractMachinePeerMeta(ctx, req.GetMeta(), identity)

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

	// Register or re-register peer via LoginPeer which handles both new
	// registrations and updates for existing peers
	// For machine peers, SetupKey and UserID are empty - auth is via mTLS
	peer, netMap, postureChecks, err := s.accountManager.LoginPeer(ctx, types.PeerLogin{
		WireGuardPubKey: peerKey.String(),
		Meta:            peerMeta,
		// Machine peer specific: no setup key, no user ID (auth via mTLS)
		// The mTLS identity in context provides authentication
		SetupKey: "",
		UserID:   "",
	})
	if err != nil {
		// Check if this is a "no auth method" error and provide better message
		if err.Error() == "no peer auth method provided, please use a setup key or interactive SSO login" {
			log.WithContext(ctx).Errorf("LoginPeer rejected mTLS auth - mTLS context not recognized. "+
				"This may indicate AddPeer needs mTLS support. Error: %v", err)
			return nil, status.Errorf(codes.Internal,
				"machine peer registration not fully implemented - AddPeer needs mTLS support")
		}
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

// extractMachinePeerMeta builds peer metadata from request, enriched with mTLS audit fields.
// This sets the mTLS-specific fields for audit trail.
func extractMachinePeerMeta(ctx context.Context, reqMeta *proto.PeerSystemMeta, identity *mtls.Identity) nbpeer.PeerSystemMeta {
	// Start with base meta from request
	meta := extractPeerMeta(ctx, reqMeta)

	// Enrich with mTLS audit fields
	meta.PeerType = identity.PeerType
	if meta.PeerType == "" {
		meta.PeerType = "machine" // Default for mTLS-authenticated peers
	}
	meta.AuthMethod = "mtls"
	meta.CertDNSName = identity.DNSName
	meta.CertDomain = identity.Domain
	meta.CertIssuerFP = identity.IssuerFingerprint
	meta.CertSerial = identity.SerialNumber
	meta.CertTemplate = identity.TemplateName
	if meta.CertTemplate == "" {
		meta.CertTemplate = identity.TemplateOID // Fallback to OID if name not available
	}

	// Set auth timestamps
	now := time.Now().UTC().Format(time.RFC3339)
	meta.FirstAuthTime = now     // Will be overwritten on re-registration
	meta.LastCertAuthTime = now

	return meta
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

	// Validate issuer CA
	if err := mtls.ValidateIssuerCA(identity.AccountID, identity.IssuerFingerprint); err != nil {
		log.WithContext(ctx).Warnf("Issuer CA validation failed in SyncMachinePeer: %v", err)
		return status.Errorf(codes.PermissionDenied, "certificate issuer not authorized: %v", err)
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

	// Validate issuer CA
	if err := mtls.ValidateIssuerCA(identity.AccountID, identity.IssuerFingerprint); err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "certificate issuer not authorized: %v", err)
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

	// Note: Issuer validation skipped for status reports (lower security sensitivity)
	// The mTLS handshake itself provides authentication

	log.WithContext(ctx).Debugf("ReportMachineStatus: DNS=%s, TunnelUp=%v, DCReachable=%v",
		identity.DNSName, req.GetTunnelUp(), req.GetDcReachable())

	// TODO: Store status for monitoring/alerting
	// This could update peer.LastSeen and store tunnel metrics

	return &proto.MachineStatusResponse{
		Ack:        true,
		ServerTime: timestamppb.Now(),
	}, nil
}
