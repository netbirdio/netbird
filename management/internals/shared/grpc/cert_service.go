package grpc

import (
	"context"
	"crypto/x509"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/ca"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// SetCAManager sets the CA manager on the server.
func (s *Server) SetCAManager(mgr *ca.Manager) {
	s.caManager = mgr
}

// SignCertificate handles a peer request to sign a certificate signing request.
func (s *Server) SignCertificate(ctx context.Context, req *proto.EncryptedMessage) (*proto.EncryptedMessage, error) {
	signReq := &proto.SignCertificateRequest{}
	peerKey, err := s.parseRequest(ctx, req, signReq)
	if err != nil {
		return nil, err
	}

	accountID, peer, err := s.authenticateExposePeer(ctx, peerKey)
	if err != nil {
		return nil, err
	}

	if s.caManager == nil {
		return nil, status.Errorf(codes.Internal, "certificate authority not available")
	}

	settings, err := s.accountManager.GetStore().GetAccountSettings(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get account settings: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to get account settings")
	}

	if !settings.CertificateAuthorityEnabled {
		return nil, status.Errorf(codes.FailedPrecondition, "certificate authority is not enabled for this account")
	}

	wildcard := signReq.Wildcard
	if wildcard && !settings.CertWildcardAllowed {
		return nil, status.Errorf(codes.PermissionDenied, "wildcard certificates are not allowed for this account")
	}

	csr, err := x509.ParseCertificateRequest(signReq.CsrDer)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid CSR: %v", err)
	}

	// Validate that the CSR FQDN matches the requesting peer's actual FQDN.
	// Without this check, a peer could request a cert for another peer's FQDN
	// within the same account domain.
	dnsDomain := s.networkMapController.GetDNSDomain(settings)
	peerFQDN := peer.FQDN(dnsDomain)
	if peerFQDN == "" {
		return nil, status.Errorf(codes.FailedPrecondition, "peer has no FQDN configured")
	}

	if err := validateCSRSANs(csr, peerFQDN, wildcard); err != nil {
		return nil, err
	}

	signingType := certSigningTypeToString(signReq.SigningType)
	trigger := ca.TriggerManual

	// For peers with login expiration enabled, tie certificate validity to the session duration.
	// Non-expiring peers get the default 90-day validity (certValidity=0).
	var certValidity time.Duration
	if peer.LoginExpirationEnabled && settings.PeerLoginExpirationEnabled && settings.PeerLoginExpiration > 0 {
		certValidity = settings.PeerLoginExpiration
	}

	if err := s.caManager.CheckRateLimit(ctx, accountID, peer.ID, trigger, settings.CertRateLimitPerPeer); err != nil {
		s.accountManager.StoreEvent(ctx, peer.ID, peer.ID, accountID, activity.CertificateRateLimited, peer.EventMeta(s.networkMapController.GetDNSDomain(settings)))
		return nil, status.Errorf(codes.ResourceExhausted, "certificate rate limit exceeded")
	}

	result, _, err := s.caManager.SignCertificate(ctx, ca.SignRequest{
		AccountID:   accountID,
		PeerID:      peer.ID,
		CSR:         csr,
		SigningType: signingType,
		Wildcard:    wildcard,
		Trigger:     trigger,
		Validity:    certValidity,
	})
	if err != nil {
		log.WithContext(ctx).Errorf("failed to sign certificate for peer %s: %v", peer.ID, err)
		return nil, status.Errorf(codes.Internal, "failed to sign certificate")
	}

	activityCode := activity.CertificateIssued
	if wildcard {
		activityCode = activity.CertificateWildcardIssued
	}
	s.accountManager.StoreEvent(ctx, peer.ID, peer.ID, accountID, activityCode, peer.EventMeta(s.networkMapController.GetDNSDomain(settings)))

	var expiresAt int64
	if notAfter, err := ca.NotAfterFromResult(result.CertPEM); err == nil {
		expiresAt = notAfter.Unix()
	}

	resp := &proto.SignCertificateResponse{
		ExpiresAt: expiresAt,
	}

	switch signingType {
	case ca.SigningTypeInternal:
		resp.InternalCertPem = result.CertPEM
		resp.InternalChainPem = result.ChainPEM
	case ca.SigningTypeACME:
		resp.AcmeCertPem = result.CertPEM
		resp.AcmeChainPem = result.ChainPEM
	}

	return s.encryptResponse(peerKey, resp)
}

// GetCACertificates handles a peer request to get the active CA certificates.
func (s *Server) GetCACertificates(ctx context.Context, req *proto.EncryptedMessage) (*proto.EncryptedMessage, error) {
	caReq := &proto.GetCACertificatesRequest{}
	peerKey, err := s.parseRequest(ctx, req, caReq)
	if err != nil {
		return nil, err
	}

	accountID, _, err := s.authenticateExposePeer(ctx, peerKey)
	if err != nil {
		return nil, err
	}

	if s.caManager == nil {
		return nil, status.Errorf(codes.Internal, "certificate authority not available")
	}

	activeCAs, err := s.caManager.GetActiveCACertificates(ctx, accountID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get CA certificates: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to get CA certificates")
	}

	certs := make([]*proto.CACertificateInfo, 0, len(activeCAs))
	for _, c := range activeCAs {
		certs = append(certs, &proto.CACertificateInfo{
			CertificatePem: []byte(c.CertificatePEM),
			Fingerprint:    c.Fingerprint,
			IsActive:       c.IsActive,
			NotAfter:       c.NotAfter.Unix(),
		})
	}

	return s.encryptResponse(peerKey, &proto.GetCACertificatesResponse{
		Certificates: certs,
	})
}

// getActiveCACertsPEM returns the PEM-encoded CA certificates for an account.
// Returns nil if the CA is not enabled or no active CAs exist.
func (s *Server) getActiveCACertsPEM(ctx context.Context, accountID string, settings *types.Settings) [][]byte {
	if s.caManager == nil || settings == nil || !settings.CertificateAuthorityEnabled {
		return nil
	}

	activeCAs, err := s.caManager.GetActiveCACertificates(ctx, accountID)
	if err != nil {
		log.WithContext(ctx).Warnf("failed to get CA certificates for sync: %v", err)
		return nil
	}

	certs := make([][]byte, 0, len(activeCAs))
	for _, c := range activeCAs {
		certs = append(certs, []byte(c.CertificatePEM))
	}
	return certs
}

// validateCSRSANs ensures the CSR contains only the expected peer FQDN (and wildcard if requested).
func validateCSRSANs(csr *x509.CertificateRequest, peerFQDN string, wildcard bool) error {
	if len(csr.IPAddresses) > 0 {
		return status.Errorf(codes.InvalidArgument, "CSR must not contain IP SANs")
	}
	if len(csr.EmailAddresses) > 0 {
		return status.Errorf(codes.InvalidArgument, "CSR must not contain Email SANs")
	}
	if len(csr.URIs) > 0 {
		return status.Errorf(codes.InvalidArgument, "CSR must not contain URI SANs")
	}

	lowerFQDN := strings.ToLower(peerFQDN)
	expected := map[string]struct{}{lowerFQDN: {}}
	if wildcard {
		expected["*."+lowerFQDN] = struct{}{}
	}
	if len(csr.DNSNames) != len(expected) {
		return status.Errorf(codes.InvalidArgument, "CSR SAN set is invalid for peer FQDN %q", peerFQDN)
	}
	seen := make(map[string]struct{}, len(csr.DNSNames))
	for _, name := range csr.DNSNames {
		lower := strings.ToLower(name)
		if _, ok := expected[lower]; !ok {
			return status.Errorf(codes.InvalidArgument, "CSR SAN %q is not allowed", name)
		}
		if _, dup := seen[lower]; dup {
			return status.Errorf(codes.InvalidArgument, "CSR contains duplicate SAN %q", name)
		}
		seen[lower] = struct{}{}
	}
	return nil
}

func certSigningTypeToString(t proto.CertSigningType) string {
	switch t {
	case proto.CertSigningType_CERT_SIGNING_ACME:
		return ca.SigningTypeACME
	default:
		return ca.SigningTypeInternal
	}
}
