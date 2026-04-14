package grpc

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	nbstatus "github.com/netbirdio/netbird/shared/management/status"
)

// deviceCertStore is the subset of store.Store needed for revocation checks.
// Defined locally to keep the dependency surface minimal and enable isolated testing.
type deviceCertStore interface {
	GetDeviceCertificateByWGKey(ctx context.Context, lockStrength store.LockingStrength, accountID, wgPubKey string) (*types.DeviceCertificate, error)
	// ListTrustedCAs returns all CA certificates registered for the account.
	// Used to verify that an external-CA cert was issued by a CA trusted within
	// this account, preventing cross-account certificate spoofing (H-5).
	ListTrustedCAs(ctx context.Context, lockStrength store.LockingStrength, accountID string) ([]*types.TrustedCA, error)
}

// checkCertRevocation verifies that the presented client certificate has not been
// administratively revoked in the store.
//
// The TLS handshake validates that the certificate was signed by a trusted CA, but
// Go's TLS stack does not automatically check CRLs.  This function enforces
// revocation via the store's Revoked flag, which is set by the admin via the
// /device-auth/devices/{id}/revoke API.
//
// Only the certificate whose serial matches the one stored for the peer's WG key is
// checked.  When a peer renews its certificate the old (revoked) row remains in the
// store; the newest cert row is returned by GetDeviceCertificateByWGKey (ORDER BY
// not_before DESC).  Presenting an old, revoked cert whose serial matches the stored
// serial will be denied.
//
// Returns nil when:
//   - no client cert was presented (cert is nil)
//   - the store returns NotFound (cert issued by an external CA, not tracked in the store)
//   - the stored serial matches and the cert is not revoked
//
// Returns PermissionDenied when:
//   - the stored serial matches and the cert is revoked
//   - the serials don't match and the cert cannot be verified against the account's CA pool
//
// Returns an Internal error when the store is unavailable (fail-closed to prevent
// revoked certs from authenticating during DB outages).
func checkCertRevocation(ctx context.Context, st deviceCertStore, accountID, wgPubKey string, cert *x509.Certificate) error {
	if cert == nil {
		return nil
	}

	dbCert, err := st.GetDeviceCertificateByWGKey(ctx, store.LockingStrengthNone, accountID, wgPubKey)
	if err != nil {
		if s, ok := nbstatus.FromError(err); ok && s.Type() == nbstatus.NotFound {
			// Cert not in our store — likely issued by an external trusted CA.
			// Verify the issuer belongs to THIS account's CA pool (H-5: cross-account spoofing).
			if verifyErr := verifyCertIssuedByAccountCA(ctx, st, accountID, cert); verifyErr != nil {
				log.WithContext(ctx).Debugf("device auth: cert issuer not in account %s CA pool for peer %s: %v", accountID, wgPubKey, verifyErr)
				return status.Errorf(codes.PermissionDenied, "device certificate was not issued by a CA trusted in this account")
			}
			return nil
		}
		// Unexpected store error (DB timeout, connection failure, etc.).
		// Fail-closed: do not allow a potentially revoked cert when we cannot check revocation.
		log.WithContext(ctx).Warnf("device auth: revocation check failed for peer %s: %v", wgPubKey, err)
		return status.Errorf(codes.Internal, "device auth: could not verify certificate revocation status")
	}

	presentedSerial := cert.SerialNumber.String()
	if dbCert.Serial != presentedSerial {
		// Serial mismatch: the store tracks a different (newer) cert for this peer's WG key.
		//
		// Conservative fail-safe: deny even if the cert was issued by the account's own CA.
		// Rationale: a peer should always present its current enrolled certificate. If the
		// serial is different, the peer is either presenting an old cert (which may have been
		// revoked prior to re-enrollment, with the revoked flag now lost on the overwritten
		// DB row) or an unknown cert. Requiring re-enrollment is the safe outcome in both cases.
		//
		// For external-CA certs that are renewed by the CA automatically (different serial,
		// same peer), the peer's enrollment flow must update the DB with the new serial.
		log.WithContext(ctx).Debugf(
			"device auth: cert serial %s does not match stored serial %s for peer %s — denying (re-enrollment required)",
			presentedSerial, dbCert.Serial, wgPubKey,
		)
		return status.Errorf(codes.PermissionDenied, "device certificate serial mismatch — please re-enroll to obtain a current certificate")
	}

	if dbCert.Revoked {
		log.WithContext(ctx).Debugf("device auth: cert serial %s revoked for peer %s", presentedSerial, wgPubKey)
		return status.Errorf(codes.PermissionDenied, "device certificate has been revoked")
	}

	return nil
}

// verifyCertIssuedByAccountCA checks that cert was issued by one of the CAs registered
// for the given account (H-5: cross-account certificate spoofing prevention).
//
// When a peer presents a cert that is not tracked in the store (NotFound), it was issued
// by an external trusted CA.  Because the global TLS cert pool is shared across all
// accounts, a cert signed by account B's CA would pass the TLS handshake even when
// connecting as a peer in account A.  This function enforces the per-account boundary.
//
// Returns nil when the cert chains to at least one of the account's registered CAs.
// Returns an error when no registered CA can verify the cert.
func verifyCertIssuedByAccountCA(ctx context.Context, st deviceCertStore, accountID string, cert *x509.Certificate) error {
	cas, err := st.ListTrustedCAs(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return fmt.Errorf("list trusted CAs for account %s: %w", accountID, err)
	}

	pool := x509.NewCertPool()
	for _, ca := range cas {
		block, _ := pem.Decode([]byte(ca.PEM))
		if block == nil {
			log.WithContext(ctx).Warnf("device auth: skipping unparseable CA PEM for account %s (CA ID: %s) — PEM decode failed", accountID, ca.ID)
			continue
		}
		caCert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			log.WithContext(ctx).Warnf("device auth: skipping invalid CA cert for account %s (CA ID: %s): %v", accountID, ca.ID, parseErr)
			continue
		}
		pool.AddCert(caCert)
	}

	opts := x509.VerifyOptions{
		Roots: pool,
		// Skip hostname check — we are verifying chain trust, not TLS server identity.
		// The TLS handshake already verified the cert is valid and unexpired.
	}
	_, err = cert.Verify(opts)
	return err
}
