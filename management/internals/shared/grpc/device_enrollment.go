package grpc

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/encryption"
	"github.com/netbirdio/netbird/management/server/deviceinventory"
	"github.com/netbirdio/netbird/management/server/devicepki"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// inventoryRecheckFailAllow is the value of DeviceAuthSettings.InventoryRecheckFailBehavior
// that allows renewal to proceed even when the MDM inventory API is unreachable.
// Any other value (including the default "deny") causes the renewal to be rejected.
const inventoryRecheckFailAllow = "allow"

// EnrollDevice handles a device certificate enrollment request (CSR submission).
// The peer encrypts a DeviceEnrollRequest; we validate the CSR and persist the
// request for admin review. The RPC is idempotent: if a pending/approved request
// already exists for this WireGuard key, we return its ID without creating a new one.
func (s *Server) EnrollDevice(ctx context.Context, req *proto.EncryptedMessage) (*proto.EncryptedMessage, error) {
	enrollReq := &proto.DeviceEnrollRequest{}
	peerKey, err := s.parseRequest(ctx, req, enrollReq)
	if err != nil {
		return nil, err
	}

	wgPubKey := peerKey.String()
	log.WithContext(ctx).Debugf("EnrollDevice: peer %s submitted CSR", wgPubKey)

	if err := validateCSRPEM(enrollReq.GetCsrPem()); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid CSR: %v", err)
	}

	st := s.accountManager.GetStore()
	accountID, err := s.accountManager.GetAccountIDForPeerKey(ctx, wgPubKey)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "peer not registered; use a setup key to register before enrolling")
	}

	// Idempotency: return the existing active request if one exists.
	existing, err := st.GetEnrollmentRequestByWGKey(ctx, store.LockingStrengthNone, accountID, wgPubKey)
	if err == nil && existing.IsActive() {
		return s.encryptEnrollResponse(peerKey, &proto.DeviceEnrollResponse{
			EnrollmentId: existing.ID,
			Status:       existing.Status,
		})
	}

	// Resolve peerID (best-effort; not required for the request to be saved).
	peerID := ""
	peer, peerErr := st.GetPeerByPeerPubKey(ctx, store.LockingStrengthNone, wgPubKey)
	if peerErr == nil {
		peerID = peer.ID
	}

	// Auto-renewal: if the peer already has a valid (non-revoked, non-expired) device
	// certificate, automatically sign the new CSR and return it without admin approval.
	// This allows trusted clients to renew their certificates without manual intervention.
	//
	// Security gate: skip auto-renewal if the most recent enrollment request for this
	// WireGuard key was explicitly rejected by an admin. A rejected enrollment means the
	// device was deliberately denied; auto-renewal must not bypass that decision.
	existingCert, certErr := st.GetDeviceCertificateByWGKey(ctx, store.LockingStrengthNone, accountID, wgPubKey)
	if certErr == nil && !existingCert.Revoked && existingCert.NotAfter.After(time.Now()) {
		prevEnroll, prevErr := st.GetEnrollmentRequestByWGKey(ctx, store.LockingStrengthNone, accountID, wgPubKey)
		if prevErr == nil && prevEnroll.Status == types.EnrollmentStatusRejected {
			// Admin explicitly rejected this device; create a new pending enrollment
			// instead of auto-renewing so the decision can be reviewed again.
			log.WithContext(ctx).Infof("EnrollDevice/autoRenew: skipping auto-renewal for peer %s — previous enrollment was rejected", wgPubKey)
		} else {
			resp, handled, err := s.tryAutoRenew(ctx, peerKey, accountID, peerID, wgPubKey, enrollReq)
			if err != nil {
				return nil, err
			}
			if handled {
				return resp, nil
			}
			// Fall through to manual enrollment if auto-renewal fails gracefully.
		}
	}

	// Inventory check for manual enrollment: when RequireInventoryCheck is enabled,
	// reject CSRs from devices not found in the configured inventory before
	// creating a pending enrollment entry. This prevents unknown devices from
	// cluttering the pending list and limits enumeration by setup-key holders.
	if err := s.checkInventoryForEnrollment(ctx, peerKey, accountID, wgPubKey, enrollReq.GetSystemInfo()); err != nil {
		return nil, err
	}

	// Attestation path: when the client provides an attestation proof and the
	// account is configured for attestation enrollment, verify the proof and
	// auto-sign the CSR without admin approval.
	if ap := enrollReq.GetAttestationProof(); ap != nil {
		resp, handled, err := s.tryAttestationEnrollment(ctx, peerKey, accountID, peerID, wgPubKey, enrollReq, ap)
		if err != nil {
			return nil, err
		}
		if handled {
			return resp, nil
		}
		// Fall through to manual enrollment if attestation is not configured.
	}

	newReq := types.NewEnrollmentRequest(accountID, peerID, wgPubKey, enrollReq.GetCsrPem(), enrollReq.GetSystemInfo())
	if err := st.SaveEnrollmentRequest(ctx, store.LockingStrengthUpdate, newReq); err != nil {
		log.WithContext(ctx).Errorf("EnrollDevice: failed to save enrollment request for peer %s: %v", wgPubKey, err)
		return nil, status.Errorf(codes.Internal, "failed to save enrollment request")
	}

	log.WithContext(ctx).Infof("EnrollDevice: created enrollment request %s for peer %s", newReq.ID, wgPubKey)

	return s.encryptEnrollResponse(peerKey, &proto.DeviceEnrollResponse{
		EnrollmentId: newReq.ID,
		Status:       newReq.Status,
	})
}

// GetEnrollmentStatus returns the current status of an enrollment request.
// When status == "approved", the response includes the issued device certificate PEM.
func (s *Server) GetEnrollmentStatus(ctx context.Context, req *proto.EncryptedMessage) (*proto.EncryptedMessage, error) {
	statusReq := &proto.EnrollmentStatusRequest{}
	peerKey, err := s.parseRequest(ctx, req, statusReq)
	if err != nil {
		return nil, err
	}

	wgPubKey := peerKey.String()
	enrollmentID := statusReq.GetEnrollmentId()
	if enrollmentID == "" {
		return nil, status.Errorf(codes.InvalidArgument, "enrollment_id is required")
	}

	st := s.accountManager.GetStore()
	accountID, err := s.accountManager.GetAccountIDForPeerKey(ctx, wgPubKey)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "peer not registered")
	}

	enrollReq, err := st.GetEnrollmentRequest(ctx, store.LockingStrengthNone, accountID, enrollmentID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "enrollment request not found")
	}

	// Verify the requesting peer owns this enrollment to prevent cross-peer information leakage.
	if enrollReq.WGPublicKey != wgPubKey {
		return nil, status.Errorf(codes.NotFound, "enrollment request not found")
	}

	resp := &proto.DeviceEnrollResponse{
		EnrollmentId: enrollReq.ID,
		Status:       enrollReq.Status,
		Reason:       enrollReq.Reason,
	}

	if enrollReq.Status == types.EnrollmentStatusApproved {
		cert, certErr := st.GetDeviceCertificateByWGKey(ctx, store.LockingStrengthNone, accountID, wgPubKey)
		if certErr == nil {
			resp.DeviceCertPem = cert.PEM
		}
	}

	return s.encryptEnrollResponse(peerKey, resp)
}

// rejectEnroll encrypts a rejection response for the given peer and returns the
// canonical three-value tuple expected by tryAttestationEnrollment.
// If encryption itself fails, returns a gRPC Internal error (handled=true so the
// caller does not fall through to manual enrollment).
func (s *Server) rejectEnroll(peerKey wgtypes.Key, reason string) (*proto.EncryptedMessage, bool, error) {
	resp, err := s.encryptEnrollResponse(peerKey, &proto.DeviceEnrollResponse{
		Status: types.EnrollmentStatusRejected,
		Reason: reason,
	})
	if err != nil {
		return nil, true, status.Errorf(codes.Internal, "encrypt rejection response: %v", err)
	}
	return resp, true, nil
}

// encryptEnrollResponse encrypts a DeviceEnrollResponse for the given peer.
func (s *Server) encryptEnrollResponse(peerKey wgtypes.Key, resp *proto.DeviceEnrollResponse) (*proto.EncryptedMessage, error) {
	serverKey, err := s.secretsManager.GetWGKey()
	if err != nil {
		return nil, fmt.Errorf("encryptEnrollResponse: get server key: %w", err)
	}
	body, err := encryption.EncryptMessage(peerKey, serverKey, resp)
	if err != nil {
		return nil, fmt.Errorf("encryptEnrollResponse: encrypt: %w", err)
	}
	return &proto.EncryptedMessage{
		WgPubKey: serverKey.PublicKey().String(),
		Body:     body,
	}, nil
}

// tryAttestationEnrollment is the old single-round TPM attestation path.
// It is disabled pending the implementation of the two-round BeginTPMAttestation /
// CompleteTPMAttestation protocol (and AttestAppleSE for Apple Secure Enclave).
//
// Returns (nil, false, nil) when ap is nil so the caller falls through to manual enrollment.
// Returns (nil, true, codes.Unimplemented) when a non-nil proof is supplied, directing
// the client to upgrade and use the new attestation RPCs.
func (s *Server) tryAttestationEnrollment(
	_ context.Context,
	_ wgtypes.Key,
	_, _, _ string,
	_ *proto.DeviceEnrollRequest,
	ap *proto.AttestationProof,
) (*proto.EncryptedMessage, bool, error) {
	if ap == nil {
		// No attestation proof: fall through to manual enrollment.
		return nil, false, nil
	}
	// The old single-round attestation protocol is disabled.
	// Clients must use BeginTPMAttestation / CompleteTPMAttestation (TPM 2.0)
	// or AttestAppleSE (Apple Secure Enclave) with an updated NetBird client.
	return nil, true, status.Errorf(codes.Unimplemented,
		"hardware attestation requires an updated NetBird client; "+
			"use manual enrollment or upgrade to a client that supports BeginTPMAttestation/AttestAppleSE")
}

// tryAutoRenew signs the CSR immediately for a peer that already has a valid certificate.
// This allows seamless certificate renewal without admin approval.
// Returns (response, true, nil) on success, (nil, false, nil) if CA is not configured,
// or (nil, true, err) on a fatal error.
func (s *Server) tryAutoRenew(
	ctx context.Context,
	peerKey wgtypes.Key,
	accountID, peerID, wgPubKey string,
	enrollReq *proto.DeviceEnrollRequest,
) (*proto.EncryptedMessage, bool, error) {
	accountSettings, err := s.accountManager.GetAccountSettings(ctx, accountID, "")
	if err != nil {
		log.WithContext(ctx).Warnf("EnrollDevice/autoRenew: could not load account settings for %s: %v", accountID, err)
		return nil, false, nil // fall through to manual
	}

	if accountSettings.DeviceAuth == nil {
		return nil, false, nil // no CA configured, fall through
	}

	// Inventory re-check: when RequireInventoryCheck is enabled and the peer's last
	// confirmation is older than InventoryRecheckIntervalHours, re-consult the MDM
	// API before issuing a new certificate. This ensures that a device removed from
	// the MDM after initial enrollment cannot silently renew its certificate indefinitely.
	//
	// Note: the serial is taken from client-supplied SystemInfo, same as manual enrollment.
	// A compromised client could supply an arbitrary serial; however this is a pre-existing
	// design constraint shared with the initial enrollment path.
	devAuth := accountSettings.DeviceAuth
	if devAuth.RequireInventoryCheck && devAuth.InventoryConfig != "" {
		// Use LockingStrengthUpdate to serialise concurrent renewals: the second
		// concurrent renewal blocks here until the first commits the updated
		// LastInventoryCheckAt timestamp, then re-evaluates shouldRecheckInventory
		// and skips the duplicate MDM call if the interval has been satisfied.
		existingCert, certErr := s.accountManager.GetStore().GetDeviceCertificateByWGKey(
			ctx, store.LockingStrengthUpdate, accountID, wgPubKey)
		if certErr == nil && existingCert != nil && shouldRecheckInventory(existingCert, devAuth.InventoryRecheckIntervalHours) {
			serial := extractSerialFromSystemInfo(enrollReq.GetSystemInfo())
			if serial == "" {
				log.WithContext(ctx).Infof("EnrollDevice/autoRenew: peer %s did not send a serial number; denying renewal", wgPubKey)
				return s.rejectEnroll(peerKey, "device serial number required for inventory re-check")
			}

			inv, invErr := deviceinventory.NewMultiInventory(devAuth.InventoryConfig)
			if invErr != nil {
				log.WithContext(ctx).Errorf("EnrollDevice/autoRenew: inventory config error for account %s: %v", accountID, invErr)
				return s.rejectEnroll(peerKey, "inventory misconfigured; contact your administrator")
			}
			updatedAt, recheckErr := performInventoryRecheck(ctx, inv, serial, existingCert)
			if recheckErr != nil {
				log.WithContext(ctx).Warnf("EnrollDevice/autoRenew: inventory re-check failed for peer %s: %v", wgPubKey, recheckErr)
				if devAuth.InventoryRecheckFailBehavior == inventoryRecheckFailAllow {
					log.WithContext(ctx).Warnf("EnrollDevice/autoRenew: proceeding despite inventory failure (fail-open configured for account %s)", accountID)
				} else {
					// Default: deny. Peer keeps its existing cert until expiry.
					return s.rejectEnroll(peerKey, "inventory check failed; retry after MDM recovers")
				}
			} else {
				// Persist the updated timestamp so future renewals within the interval skip the MDM call.
				updatedCert := *existingCert
				updatedCert.LastInventoryCheckAt = updatedAt
				if saveErr := s.accountManager.GetStore().SaveDeviceCertificate(ctx, store.LockingStrengthUpdate, &updatedCert); saveErr != nil {
					log.WithContext(ctx).Warnf("EnrollDevice/autoRenew: could not update LastInventoryCheckAt for peer %s: %v", wgPubKey, saveErr)
				}
			}
		}
	}

	block, _ := pem.Decode([]byte(enrollReq.GetCsrPem()))
	if block == nil {
		return s.rejectEnroll(peerKey, "invalid CSR in renewal request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return s.rejectEnroll(peerKey, "failed to parse CSR in renewal request")
	}

	ca, err := devicepki.NewCA(ctx, accountSettings.DeviceAuth, accountID, s.accountManager.GetStore(), s.config.ManagementURL)
	if err != nil {
		log.WithContext(ctx).Errorf("EnrollDevice/autoRenew: load CA for account %s: %v", accountID, err)
		return nil, true, status.Errorf(codes.Internal, "failed to load certificate authority")
	}

	validityDays := accountSettings.DeviceAuth.CertValidityDays
	if validityDays <= 0 {
		validityDays = 365
	}

	cert, err := ca.SignCSR(ctx, csr, wgPubKey, validityDays)
	if err != nil {
		log.WithContext(ctx).Errorf("EnrollDevice/autoRenew: sign CSR for peer %s: %v", wgPubKey, err)
		return nil, true, status.Errorf(codes.Internal, "failed to sign renewal certificate")
	}

	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))

	st := s.accountManager.GetStore()
	newDevCert := types.NewDeviceCertificate(
		accountID, peerID, wgPubKey,
		cert.SerialNumber.String(), certPEM,
		cert.NotBefore, cert.NotAfter,
	)
	if saveErr := st.SaveDeviceCertificate(ctx, store.LockingStrengthUpdate, newDevCert); saveErr != nil {
		log.WithContext(ctx).Errorf("EnrollDevice/autoRenew: save cert for peer %s: %v", wgPubKey, saveErr)
		return nil, true, status.Errorf(codes.Internal, "failed to save renewed certificate")
	}

	// Save an approved enrollment record for audit.
	newReq := types.NewEnrollmentRequest(accountID, peerID, wgPubKey, enrollReq.GetCsrPem(), enrollReq.GetSystemInfo())
	newReq.Status = types.EnrollmentStatusApproved
	if saveErr := st.SaveEnrollmentRequest(ctx, store.LockingStrengthUpdate, newReq); saveErr != nil {
		log.WithContext(ctx).Warnf("EnrollDevice/autoRenew: save enrollment record for peer %s: %v", wgPubKey, saveErr)
	}

	log.WithContext(ctx).Infof("EnrollDevice/autoRenew: renewed cert serial %s for peer %s (expires %s)",
		cert.SerialNumber, wgPubKey, cert.NotAfter.Format("2006-01-02"))

	resp, encErr := s.encryptEnrollResponse(peerKey, &proto.DeviceEnrollResponse{
		EnrollmentId:  newReq.ID,
		Status:        types.EnrollmentStatusApproved,
		DeviceCertPem: certPEM,
	})
	if encErr != nil {
		return nil, true, status.Errorf(codes.Internal, "encrypt auto-renewal response: %v", encErr)
	}
	return resp, true, nil
}

// checkInventoryForEnrollment verifies the enrolling device against the account's
// inventory when RequireInventoryCheck is enabled. Returns nil when the check
// passes or is not configured. Returns a gRPC status error on failure so that
// the caller can propagate it directly.
//
// This is intentionally a hard gate for NEW enrollments: unknown devices are
// rejected before a pending entry is created, keeping the admin review queue clean.
// The check is skipped for auto-renewal (peer already has a valid cert) and
// for attestation enrollment (which performs its own inventory check).
func (s *Server) checkInventoryForEnrollment(ctx context.Context, peerKey wgtypes.Key, accountID, wgPubKey, systemInfo string) error {
	settings, err := s.accountManager.GetAccountSettings(ctx, accountID, "")
	if err != nil {
		log.WithContext(ctx).Errorf("EnrollDevice/inventoryCheck: could not load settings for account %s: %v", accountID, err)
		return status.Errorf(codes.Unavailable, "enrollment temporarily unavailable; please retry later")
	}

	devAuth := settings.DeviceAuth
	if devAuth == nil || !devAuth.RequireInventoryCheck || devAuth.InventoryConfig == "" {
		return nil // inventory check not configured
	}

	serial := extractSerialFromSystemInfo(systemInfo)
	if serial == "" {
		log.WithContext(ctx).Infof("EnrollDevice/inventoryCheck: peer %s did not send a serial number, rejecting", wgPubKey)
		// Return an encrypted rejection so the client can display a meaningful message.
		// We wrap the rejection in a status error because checkInventoryForEnrollment
		// cannot return an EncryptedMessage directly. The caller returns the gRPC error.
		return status.Errorf(codes.InvalidArgument,
			"device serial number is required for enrollment (set require_inventory_check is enabled on the account)")
	}

	inv, invErr := deviceinventory.NewMultiInventory(devAuth.InventoryConfig)
	if invErr != nil {
		log.WithContext(ctx).Errorf("EnrollDevice/inventoryCheck: build inventory for account %s: %v", accountID, invErr)
		return status.Errorf(codes.Internal, "device inventory misconfigured; contact your administrator")
	}

	registered, invCheckErr := inv.IsRegistered(ctx, serial)
	if invCheckErr != nil {
		log.WithContext(ctx).Warnf("EnrollDevice/inventoryCheck: check error for peer %s (serial %s): %v", wgPubKey, serial, invCheckErr)
		return status.Errorf(codes.Unavailable, "device inventory check failed; please retry later")
	}

	if !registered {
		log.WithContext(ctx).Infof("EnrollDevice/inventoryCheck: peer %s (serial %s) not in inventory, rejected", wgPubKey, serial)
		return status.Errorf(codes.PermissionDenied,
			"device serial %s is not registered in the corporate device inventory", serial)
	}

	log.WithContext(ctx).Debugf("EnrollDevice/inventoryCheck: peer %s (serial %s) found in inventory", wgPubKey, serial)
	return nil
}

// extractSerialFromSystemInfo parses the SystemSerialNumber from a JSON-encoded
// PeerSystemMeta blob. Returns an empty string if the field is absent or the
// JSON cannot be parsed.
func extractSerialFromSystemInfo(systemInfo string) string {
	if systemInfo == "" {
		return ""
	}
	var meta struct {
		SystemSerialNumber string `json:"SystemSerialNumber"`
	}
	if err := json.Unmarshal([]byte(systemInfo), &meta); err != nil {
		return ""
	}
	return meta.SystemSerialNumber
}

// shouldRecheckInventory returns true when the peer's last inventory confirmation is
// older than the configured interval (or has never been done).
// intervalHours == 0 means always re-check (every renewal triggers the MDM call).
// intervalHours < 0 is treated as 24 (defensive default).
func shouldRecheckInventory(cert *types.DeviceCertificate, intervalHours int) bool {
	if intervalHours == 0 {
		return true // always recheck
	}
	if intervalHours < 0 {
		intervalHours = 24
	}
	return cert.LastInventoryCheckAt == nil ||
		time.Since(*cert.LastInventoryCheckAt) > time.Duration(intervalHours)*time.Hour
}

// performInventoryRecheck checks whether the device is still in the inventory.
// On success it returns a non-nil timestamp that the caller should persist to
// DeviceCertificate.LastInventoryCheckAt.
// On failure (device absent or API error) it returns (nil, err).
func performInventoryRecheck(ctx context.Context, inv deviceinventory.Inventory, serial string, cert *types.DeviceCertificate) (*time.Time, error) {
	registered, err := inv.IsRegistered(ctx, serial)
	if err != nil {
		return nil, fmt.Errorf("inventory check failed for peer %s: %w", cert.WGPublicKey, err)
	}
	if !registered {
		return nil, fmt.Errorf("device no longer registered in inventory (peer %s)", cert.WGPublicKey)
	}
	now := time.Now().UTC()
	return &now, nil
}

// parseCSRPEM decodes, validates, and returns the parsed CertificateRequest from a
// PEM-encoded CERTIFICATE REQUEST block.
func parseCSRPEM(csrPEM string) (*x509.CertificateRequest, error) {
	if csrPEM == "" {
		return nil, fmt.Errorf("CSR is empty")
	}
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	if block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("unexpected PEM type %q (want CERTIFICATE REQUEST)", block.Type)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature verification failed: %w", err)
	}
	return csr, nil
}

// validateCSRPEM checks that the PEM block is a CERTIFICATE REQUEST and that
// the embedded CSR signature is self-consistent.
func validateCSRPEM(csrPEM string) error {
	_, err := parseCSRPEM(csrPEM)
	return err
}
