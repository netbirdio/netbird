// Package device_auth provides HTTP API handlers for device certificate authentication.
// Admins use these endpoints to manage enrollment requests, trusted CAs, and certificates.
package device_auth

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/devicepki"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

// certPoolUpdater is the subset of deviceauth.DeviceAuthHandler needed to rebuild the cert pool.
// Defined locally to avoid an import cycle between device_auth handler and deviceauth package.
type certPoolUpdater interface {
	UpdateCertPool(pool *x509.CertPool)
}

// peerDisconnecter is the narrow interface we need from the network map controller.
// Using a local interface keeps the handler decoupled from the full Controller and
// allows tests to supply a simple mock without implementing all Controller methods.
type peerDisconnecter interface {
	DisconnectPeers(ctx context.Context, accountId string, peerIDs []string)
}

type handler struct {
	store                store.Store
	poolUpdater          certPoolUpdater  // may be nil if device auth handler is not wired
	managementURL        string
	networkMapController peerDisconnecter // may be nil in tests; used to disconnect revoked peers
	// caFactory creates a CA backend for the given settings. Defaults to devicepki.NewCA.
	// Overriding this field allows tests to inject a mock CA without a live backend.
	caFactory func(ctx context.Context, settings *types.DeviceAuthSettings, accountID string, st store.Store, managementURL string) (devicepki.CA, error)
}

// isNotFoundErr returns true when err is a status.Error with type status.NotFound.
func isNotFoundErr(err error) bool {
	if s, ok := status.FromError(err); ok && s != nil {
		return s.ErrorType == status.NotFound
	}
	return false
}

// AddEndpoints registers device auth admin endpoints on router.
// poolUpdater is optional; when non-nil the trusted CA pool is rebuilt automatically
// whenever a trusted CA is added or removed.
// managementURL is the externally accessible server URL used to build CRL distribution
// point URLs embedded in issued device certificates.
func AddEndpoints(st store.Store, poolUpdater certPoolUpdater, managementURL string, nmc peerDisconnecter, router *mux.Router) {
	h := &handler{
		store:                st,
		poolUpdater:          poolUpdater,
		managementURL:        managementURL,
		networkMapController: nmc,
		caFactory:            devicepki.NewCA,
	}
	addEndpointsToHandler(h, router)
}

// addEndpointsToHandler registers all routes on router for the given handler.
// Extracted from AddEndpoints to allow tests to inject a custom handler (e.g. with a mock CA factory).
func addEndpointsToHandler(h *handler, router *mux.Router) {
	// Enrollment requests
	router.HandleFunc("/device-auth/enrollments", h.listEnrollments).Methods("GET", "OPTIONS")
	router.HandleFunc("/device-auth/enrollments/{id}/approve", h.approveEnrollment).Methods("POST", "OPTIONS")
	router.HandleFunc("/device-auth/enrollments/{id}/reject", h.rejectEnrollment).Methods("POST", "OPTIONS")

	// Device certificates
	router.HandleFunc("/device-auth/devices", h.listDevices).Methods("GET", "OPTIONS")
	router.HandleFunc("/device-auth/devices/{id}/revoke", h.revokeDevice).Methods("POST", "OPTIONS")
	router.HandleFunc("/device-auth/devices/{id}/cert/renew", h.renewDeviceCert).Methods("POST", "OPTIONS")

	// Trusted CAs
	router.HandleFunc("/device-auth/trusted-cas", h.listTrustedCAs).Methods("GET", "OPTIONS")
	router.HandleFunc("/device-auth/trusted-cas", h.createTrustedCA).Methods("POST", "OPTIONS")
	router.HandleFunc("/device-auth/trusted-cas/{id}", h.deleteTrustedCA).Methods("DELETE", "OPTIONS")

	// CRL download (token-based path to prevent account enumeration)
	router.HandleFunc("/device-auth/crl/{token}", h.getCRL).Methods("GET", "OPTIONS")

	// Device auth settings (read / update)
	router.HandleFunc("/device-auth/settings", h.getSettings).Methods("GET", "OPTIONS")
	router.HandleFunc("/device-auth/settings", h.updateSettings).Methods("PUT", "OPTIONS")

	// CA-specific configuration (read / update with credential redaction)
	router.HandleFunc("/device-auth/ca/config", h.getCAConfig).Methods("GET", "OPTIONS")
	router.HandleFunc("/device-auth/ca/config", h.putCAConfig).Methods("PUT", "OPTIONS")

	// CA connectivity test
	router.HandleFunc("/device-auth/ca/test", h.postCATest).Methods("POST", "OPTIONS")

	// Inventory-specific configuration (read / update with credential redaction)
	router.HandleFunc("/device-auth/inventory/config", h.getInventoryConfig).Methods("GET", "OPTIONS")
	router.HandleFunc("/device-auth/inventory/config", h.putInventoryConfig).Methods("PUT", "OPTIONS")
}

// requireAdmin returns the UserAuth for the request and ensures the caller has admin or owner
// privileges. It writes an appropriate HTTP error and returns false when the check fails.
func (h *handler) requireAdmin(w http.ResponseWriter, r *http.Request) (userAuth auth.UserAuth, ok bool) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return userAuth, false
	}

	if userAuth.UserId == "" || userAuth.AccountId == "" {
		util.WriteError(r.Context(), status.Errorf(status.PermissionDenied, "admin access required"), w)
		return userAuth, false
	}

	user, err := h.store.GetUserByUserID(r.Context(), store.LockingStrengthNone, userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return userAuth, false
	}

	if !user.HasAdminPower() {
		util.WriteError(r.Context(), status.Errorf(status.PermissionDenied, "admin access required"), w)
		return userAuth, false
	}

	if user.AccountID != userAuth.AccountId {
		util.WriteError(r.Context(), status.Errorf(status.PermissionDenied, "account mismatch"), w)
		return userAuth, false
	}

	return userAuth, true
}

// requireAdminOrCertApprover returns the UserAuth and ensures the caller has admin, owner,
// or cert_approver privileges. Used for enrollment management endpoints.
func (h *handler) requireAdminOrCertApprover(w http.ResponseWriter, r *http.Request) (userAuth auth.UserAuth, ok bool) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return userAuth, false
	}

	if userAuth.UserId == "" || userAuth.AccountId == "" {
		util.WriteError(r.Context(), status.Errorf(status.PermissionDenied, "authentication required"), w)
		return userAuth, false
	}

	user, err := h.store.GetUserByUserID(r.Context(), store.LockingStrengthNone, userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return userAuth, false
	}

	if !user.HasAdminPower() && user.Role != types.UserRoleCertApprover {
		util.WriteError(r.Context(), status.Errorf(status.PermissionDenied, "admin or cert_approver access required"), w)
		return userAuth, false
	}

	if user.AccountID != userAuth.AccountId {
		util.WriteError(r.Context(), status.Errorf(status.PermissionDenied, "account mismatch"), w)
		return userAuth, false
	}

	return userAuth, true
}

// listEnrollments returns all enrollment requests for the account.
func (h *handler) listEnrollments(w http.ResponseWriter, r *http.Request) {
	userAuth, ok := h.requireAdminOrCertApprover(w, r)
	if !ok {
		return
	}

	reqs, err := h.store.ListEnrollmentRequests(r.Context(), store.LockingStrengthNone, userAuth.AccountId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, toEnrollmentResponseList(reqs))
}

// approveEnrollment signs the CSR and issues a device certificate.
func (h *handler) approveEnrollment(w http.ResponseWriter, r *http.Request) {
	userAuth, ok := h.requireAdminOrCertApprover(w, r)
	if !ok {
		return
	}

	id := mux.Vars(r)["id"]
	// Use LockingStrengthUpdate (SELECT FOR UPDATE) to serialize concurrent admin approvals
	// and prevent duplicate certificate issuance from a TOCTOU race.
	enrollReq, err := h.store.GetEnrollmentRequest(r.Context(), store.LockingStrengthUpdate, userAuth.AccountId, id)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	if enrollReq.Status != types.EnrollmentStatusPending {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "enrollment is not in pending state"), w)
		return
	}

	// Resolve account settings to get validityDays and CA config.
	settings, err := h.store.GetAccountSettings(r.Context(), store.LockingStrengthNone, userAuth.AccountId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	validityDays := 365
	if settings.DeviceAuth != nil && settings.DeviceAuth.CertValidityDays > 0 {
		validityDays = settings.DeviceAuth.CertValidityDays
	}

	// Load the account CA. newBuiltinCA creates one if none is persisted yet.
	ca, caErr := h.caFactory(r.Context(), settings.DeviceAuth, userAuth.AccountId, h.store, h.managementURL)
	if caErr != nil {
		util.WriteError(r.Context(), caErr, w)
		return
	}

	peerID := enrollReq.PeerID

	// Parse and sign the CSR.
	csr, parseErr := parsePEMCSR(enrollReq.CSRPEM)
	if parseErr != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid CSR in enrollment request: %v", parseErr), w)
		return
	}

	cert, signErr := ca.SignCSR(r.Context(), csr, enrollReq.WGPublicKey, validityDays)
	if signErr != nil {
		util.WriteError(r.Context(), signErr, w)
		return
	}

	issuedPEM := certToPEM(cert.Raw)

	// Save the device certificate.
	devCert := types.NewDeviceCertificate(
		userAuth.AccountId,
		peerID,
		enrollReq.WGPublicKey,
		cert.SerialNumber.String(),
		issuedPEM,
		cert.NotBefore,
		cert.NotAfter,
	)
	if err := h.store.SaveDeviceCertificate(r.Context(), store.LockingStrengthUpdate, devCert); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	// Update enrollment status — copy before modifying to avoid mutating the store-returned value.
	updated := *enrollReq
	updated.Status = types.EnrollmentStatusApproved
	now := time.Now().UTC()
	updated.UpdatedAt = now
	if err := h.store.SaveEnrollmentRequest(r.Context(), store.LockingStrengthUpdate, &updated); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, toEnrollmentResponse(&updated))
}

// rejectEnrollment rejects a pending enrollment request.
func (h *handler) rejectEnrollment(w http.ResponseWriter, r *http.Request) {
	userAuth, ok := h.requireAdminOrCertApprover(w, r)
	if !ok {
		return
	}

	id := mux.Vars(r)["id"]
	// Use LockingStrengthUpdate to prevent TOCTOU races with concurrent admin actions.
	enrollReq, err := h.store.GetEnrollmentRequest(r.Context(), store.LockingStrengthUpdate, userAuth.AccountId, id)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	if enrollReq.Status != types.EnrollmentStatusPending {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "enrollment is not in pending state"), w)
		return
	}

	var body struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		// An empty body (io.EOF) means no reason was provided — that's fine.
		// Any other decode error means the JSON is malformed.
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	// Copy before modifying to avoid mutating the store-returned value.
	updated := *enrollReq
	updated.Status = types.EnrollmentStatusRejected
	updated.Reason = body.Reason
	updated.UpdatedAt = time.Now().UTC()

	if err := h.store.SaveEnrollmentRequest(r.Context(), store.LockingStrengthUpdate, &updated); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, toEnrollmentResponse(&updated))
}

// listDevices returns all device certificates for the account.
func (h *handler) listDevices(w http.ResponseWriter, r *http.Request) {
	userAuth, ok := h.requireAdminOrCertApprover(w, r)
	if !ok {
		return
	}

	certs, err := h.store.ListDeviceCertificates(r.Context(), store.LockingStrengthNone, userAuth.AccountId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, toCertResponseList(certs))
}

// revokeDevice marks a device certificate as revoked.
func (h *handler) revokeDevice(w http.ResponseWriter, r *http.Request) {
	userAuth, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}

	id := mux.Vars(r)["id"]
	// Use LockingStrengthUpdate to serialize concurrent revocations of the same cert.
	cert, err := h.store.GetDeviceCertificateByID(r.Context(), store.LockingStrengthUpdate, userAuth.AccountId, id)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	if cert.Revoked {
		util.WriteJSONObject(r.Context(), w, toCertResponse(cert)) // idempotent
		return
	}

	// Copy before modifying to avoid mutating the store-returned value.
	revokedCert := *cert
	now := time.Now().UTC()
	revokedCert.Revoked = true
	revokedCert.RevokedAt = &now

	if err := h.store.SaveDeviceCertificate(r.Context(), store.LockingStrengthUpdate, &revokedCert); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	// Force-close any active Sync stream for this peer so that the revocation
	// takes effect immediately. On reconnect, Login's checkCertRevocation will
	// reject the revoked certificate before issuing a new Sync stream.
	if h.networkMapController != nil {
		peer, pErr := h.store.GetPeerByPeerPubKey(r.Context(), store.LockingStrengthShare, revokedCert.WGPublicKey)
		switch {
		case pErr == nil && peer != nil:
			h.networkMapController.DisconnectPeers(r.Context(), userAuth.AccountId, []string{peer.ID})
		case pErr != nil && !isNotFoundErr(pErr):
			// Transient store error: revocation is durable but the peer may keep its
			// active Sync stream until it reconnects and Login rejects the cert.
			log.WithContext(r.Context()).WithError(pErr).Warn("revokeDevice: peer lookup failed; active Sync stream may persist until reconnect")
		}
	}

	util.WriteJSONObject(r.Context(), w, toCertResponse(&revokedCert))
}

// renewDeviceCert revokes the current certificate for a device and resets its
// enrollment request to "pending" so that the client will re-enroll on its next
// certificate check.
//
// For Mode A (manual enrollment) the new CSR will require admin approval.
// For Mode C (attestation enrollment) the new enrollment will be automatically
// approved when the client submits a valid AttestationProof.
func (h *handler) renewDeviceCert(w http.ResponseWriter, r *http.Request) {
	userAuth, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}

	id := mux.Vars(r)["id"]
	// Use LockingStrengthUpdate to serialize concurrent renewal calls for the same cert.
	cert, err := h.store.GetDeviceCertificateByID(r.Context(), store.LockingStrengthUpdate, userAuth.AccountId, id)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	// Revoke the existing certificate in the store.
	// Note: CA-backend revocation (e.g. Vault/Smallstep RevokeCert) is intentionally
	// omitted here; CheckDeviceAuth relies on the store's Revoked flag, not the CA CRL.
	// External CRL consumers should treat store-revoked certs as untrusted.
	revokedCert := *cert
	if !cert.Revoked {
		// Copy before modifying to avoid mutating the store-returned value.
		now := time.Now().UTC()
		revokedCert.Revoked = true
		revokedCert.RevokedAt = &now
		if err := h.store.SaveDeviceCertificate(r.Context(), store.LockingStrengthUpdate, &revokedCert); err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
	}

	// Reset the existing enrollment request to pending so the client re-submits a CSR.
	enrollReq, enrollErr := h.store.GetEnrollmentRequestByWGKey(r.Context(), store.LockingStrengthUpdate, userAuth.AccountId, cert.WGPublicKey)
	if enrollErr != nil {
		// No prior enrollment found — the device cert was issued outside the normal flow.
		// The cert is already revoked; the device will need to re-enroll from scratch.
		log.Warnf("device_auth: renewDeviceCert: no enrollment request found for WG key %s: %v", cert.WGPublicKey, enrollErr)
	} else {
		// Copy before modifying to avoid mutating the store-returned value.
		updatedEnroll := *enrollReq
		updatedEnroll.Status = types.EnrollmentStatusPending
		updatedEnroll.Reason = "renewal initiated by admin"
		updatedEnroll.UpdatedAt = time.Now().UTC()
		if saveErr := h.store.SaveEnrollmentRequest(r.Context(), store.LockingStrengthUpdate, &updatedEnroll); saveErr != nil {
			log.Errorf("device_auth: renewDeviceCert: reset enrollment %s: %v", updatedEnroll.ID, saveErr)
			util.WriteError(r.Context(), saveErr, w)
			return
		}
	}

	util.WriteJSONObject(r.Context(), w, toCertResponse(&revokedCert))
}

// listTrustedCAs returns all trusted CA records for the account.
func (h *handler) listTrustedCAs(w http.ResponseWriter, r *http.Request) {
	userAuth, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}

	cas, err := h.store.ListTrustedCAs(r.Context(), store.LockingStrengthNone, userAuth.AccountId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, toCAResponseList(cas))
}

// createTrustedCA adds a new trusted CA (e.g. an imported external CA PEM).
func (h *handler) createTrustedCA(w http.ResponseWriter, r *http.Request) {
	userAuth, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}

	var body struct {
		Name string `json:"name"`
		PEM  string `json:"pem"`
	}
	// Limit body to 1 MiB: PEM blobs are typically a few KiB.
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	if body.Name == "" || body.PEM == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "name and pem are required"), w)
		return
	}

	caCert, err := parsePEMCert(body.PEM)
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid certificate PEM: %v", err), w)
		return
	}
	if err := validateCACert(caCert); err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid CA certificate: %v", err), w)
		return
	}

	ca := types.NewTrustedCA(userAuth.AccountId, body.Name, body.PEM)
	if err := h.store.SaveTrustedCA(r.Context(), store.LockingStrengthUpdate, ca); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	h.rebuildCertPool(r)

	util.WriteJSONObject(r.Context(), w, toCAResponse(ca))
}

// deleteTrustedCA removes a trusted CA by ID.
func (h *handler) deleteTrustedCA(w http.ResponseWriter, r *http.Request) {
	userAuth, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}

	id := mux.Vars(r)["id"]
	if err := h.store.DeleteTrustedCA(r.Context(), userAuth.AccountId, id); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	h.rebuildCertPool(r)

	util.WriteJSONObject(r.Context(), w, emptyObject{})
}

// getCRL generates and returns a DER-encoded CRL for the builtin CA identified
// by a random token in the URL path.
//
// The endpoint is publicly accessible (no auth required) so that PKI relying
// parties can check certificate revocation without credentials. An unknown or
// missing token returns 404 — not 401 or 403 — to avoid revealing that the
// endpoint exists and prevent account enumeration.
//
// Route: GET /api/device-auth/crl/{token}
func (h *handler) getCRL(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	token := mux.Vars(r)["token"]
	// Reject tokens that are not exactly 64 lowercase hex characters (32 bytes).
	// This avoids unnecessary DB lookups for malformed inputs and prevents
	// timing-based probing for valid tokens via response-time differences.
	if len(token) != 64 {
		http.NotFound(w, r)
		return
	}
	if _, hexErr := hex.DecodeString(token); hexErr != nil {
		http.NotFound(w, r)
		return
	}

	trustedCA, err := h.store.GetTrustedCAByCRLToken(ctx, token)
	if err != nil {
		// Unknown token → 404 (do not reveal whether the endpoint exists)
		http.NotFound(w, r)
		return
	}

	// Load the builtin CA to sign the CRL. We pass an empty cdpURL because
	// the CRL itself does not need to reference its own distribution point.
	loaded, err := devicepki.LoadBuiltinCA(trustedCA.PEM, trustedCA.KeyPEM, "")
	if err != nil {
		// Return 404 even for internal failures so that a valid token cannot be
		// inferred from the response code (timing side-channel prevention).
		log.WithContext(ctx).Errorf("getCRL: failed to load builtin CA: %v", err)
		http.NotFound(w, r)
		return
	}

	// Populate revoked serials from the store. The in-memory revocation list
	// inside BuiltinCA is empty after every LoadBuiltinCA call.
	certs, err := h.store.ListDeviceCertificates(ctx, store.LockingStrengthNone, trustedCA.AccountID)
	if err != nil {
		log.WithContext(ctx).Errorf("getCRL: failed to list device certificates: %v", err)
		http.NotFound(w, r)
		return
	}
	for _, c := range certs {
		if c.Revoked {
			if rErr := loaded.RevokeCert(ctx, c.Serial); rErr != nil {
				log.WithContext(ctx).Warnf("getCRL: skipping invalid serial %s: %v", c.Serial, rErr)
			}
		}
	}

	crlDER, err := loaded.GenerateCRL(ctx)
	if err != nil {
		log.WithContext(ctx).Errorf("getCRL: failed to generate CRL: %v", err)
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(crlDER)
}

// getSettings returns the current DeviceAuthSettings for the account.
func (h *handler) getSettings(w http.ResponseWriter, r *http.Request) {
	userAuth, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}

	accountSettings, err := h.store.GetAccountSettings(r.Context(), store.LockingStrengthNone, userAuth.AccountId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	resp := defaultDeviceAuthSettingsResponse()
	if accountSettings.DeviceAuth != nil {
		resp = toDeviceAuthSettingsResponse(accountSettings.DeviceAuth)
	}
	util.WriteJSONObject(r.Context(), w, resp)
}

// updateSettings replaces the DeviceAuthSettings for the account.
func (h *handler) updateSettings(w http.ResponseWriter, r *http.Request) {
	userAuth, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}

	var req deviceAuthSettingsRequest
	// Limit body to 1 MiB to prevent memory exhaustion from oversized payloads.
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	// Use LockingStrengthUpdate to serialize concurrent settings updates (prevent last-writer-wins race).
	accountSettings, err := h.store.GetAccountSettings(r.Context(), store.LockingStrengthUpdate, userAuth.AccountId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	if accountSettings.DeviceAuth == nil {
		accountSettings.DeviceAuth = &types.DeviceAuthSettings{}
	}

	// Validate enum fields and bounds before applying changes.
	if req.Mode != nil {
		switch *req.Mode {
		case types.DeviceAuthModeDisabled, types.DeviceAuthModeOptional,
			types.DeviceAuthModeCertOnly, types.DeviceAuthModeCertAndSSO:
		default:
			util.WriteErrorResponse(fmt.Sprintf("invalid mode %q", *req.Mode), http.StatusBadRequest, w)
			return
		}
	}
	if req.EnrollmentMode != nil {
		switch *req.EnrollmentMode {
		case types.DeviceAuthEnrollmentManual, types.DeviceAuthEnrollmentAttestation, types.DeviceAuthEnrollmentBoth:
		default:
			util.WriteErrorResponse(fmt.Sprintf("invalid enrollment_mode %q", *req.EnrollmentMode), http.StatusBadRequest, w)
			return
		}
	}
	if req.CAType != nil {
		switch *req.CAType {
		case types.DeviceAuthCATypeBuiltin, types.DeviceAuthCATypeVault,
			types.DeviceAuthCATypeSmallstep, types.DeviceAuthCATypeSCEP:
		default:
			util.WriteErrorResponse(fmt.Sprintf("invalid ca_type %q", *req.CAType), http.StatusBadRequest, w)
			return
		}
	}
	if req.InventoryType != nil {
		switch *req.InventoryType {
		case "", "static", "intune", "jamf":
		default:
			util.WriteErrorResponse(fmt.Sprintf("invalid inventory_type %q", *req.InventoryType), http.StatusBadRequest, w)
			return
		}
	}
	if req.CertValidityDays != nil && (*req.CertValidityDays < 1 || *req.CertValidityDays > 3650) {
		util.WriteErrorResponse("cert_validity_days must be between 1 and 3650", http.StatusBadRequest, w)
		return
	}

	// Apply only the fields present in the request.
	if req.Mode != nil {
		accountSettings.DeviceAuth.Mode = *req.Mode
	}
	if req.EnrollmentMode != nil {
		accountSettings.DeviceAuth.EnrollmentMode = *req.EnrollmentMode
	}
	if req.CAType != nil {
		accountSettings.DeviceAuth.CAType = *req.CAType
	}
	if req.CAConfig != nil {
		accountSettings.DeviceAuth.CAConfig = *req.CAConfig
	}
	if req.CertValidityDays != nil {
		accountSettings.DeviceAuth.CertValidityDays = *req.CertValidityDays
	}
	if req.OCSPEnabled != nil {
		accountSettings.DeviceAuth.OCSPEnabled = *req.OCSPEnabled
	}
	if req.FailOpenOnOCSPUnavailable != nil {
		accountSettings.DeviceAuth.FailOpenOnOCSPUnavailable = *req.FailOpenOnOCSPUnavailable
	}
	if req.InventoryType != nil {
		accountSettings.DeviceAuth.InventoryType = *req.InventoryType
	}
	if req.InventoryConfig != nil {
		accountSettings.DeviceAuth.InventoryConfig = *req.InventoryConfig
	}
	if req.RequireInventoryCheck != nil {
		accountSettings.DeviceAuth.RequireInventoryCheck = *req.RequireInventoryCheck
	}

	if err := h.store.SaveAccountSettings(r.Context(), userAuth.AccountId, accountSettings); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, toDeviceAuthSettingsResponse(accountSettings.DeviceAuth))
}

// rebuildCertPool reloads all trusted CAs across ALL accounts from the store and
// pushes the updated pool to the device auth handler (if wired).
//
// The cert pool is global: it holds every account's CAs so that the TLS layer
// can accept a device certificate regardless of which account it belongs to.
// Account-level enforcement happens in CheckDeviceAuth, not in the TLS handshake.
//
// Performance note: this performs an O(N) full-scan across all accounts.
// For large multi-tenant deployments a future improvement should maintain an
// incremental pool (add/remove individual CA certs) or use a single
// ListAllTrustedCAs store query instead of per-account calls.
func (h *handler) rebuildCertPool(r *http.Request) {
	if h.poolUpdater == nil {
		return
	}

	accounts := h.store.GetAllAccounts(r.Context())
	if len(accounts) == 0 {
		log.Warn("device_auth: rebuildCertPool: GetAllAccounts returned empty, skipping pool update to avoid clearing active certificates")
		return
	}

	pool := x509.NewCertPool()
	for _, acct := range accounts {
		cas, err := h.store.ListTrustedCAs(r.Context(), store.LockingStrengthNone, acct.Id)
		if err != nil {
			log.Warnf("device_auth: rebuild cert pool: list CAs for account %s: %v", acct.Id, err)
			continue
		}
		for _, ca := range cas {
			pool.AppendCertsFromPEM([]byte(ca.PEM))
		}
	}

	h.poolUpdater.UpdateCertPool(pool)
}

// ─── Response types ────────────────────────────────────────────────────────────

type enrollmentResponse struct {
	ID          string `json:"id"`
	PeerID      string `json:"peer_id"`
	WGPublicKey string `json:"wg_public_key"`
	Status      string `json:"status"`
	Reason      string `json:"reason,omitempty"`
	CreatedAt   string `json:"created_at"`
}

type certResponse struct {
	ID          string  `json:"id"`
	PeerID      string  `json:"peer_id"`
	WGPublicKey string  `json:"wg_public_key"`
	Serial      string  `json:"serial"`
	NotBefore   string  `json:"not_before"`
	NotAfter    string  `json:"not_after"`
	Revoked     bool    `json:"revoked"`
	RevokedAt   *string `json:"revoked_at,omitempty"`
}

type caResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
	PEM       string `json:"pem"`
}

type emptyObject struct{}

func toEnrollmentResponse(r *types.EnrollmentRequest) enrollmentResponse {
	return enrollmentResponse{
		ID:          r.ID,
		PeerID:      r.PeerID,
		WGPublicKey: r.WGPublicKey,
		Status:      r.Status,
		Reason:      r.Reason,
		CreatedAt:   r.CreatedAt.UTC().Format(time.RFC3339),
	}
}

func toEnrollmentResponseList(reqs []*types.EnrollmentRequest) []enrollmentResponse {
	out := make([]enrollmentResponse, 0, len(reqs))
	for _, r := range reqs {
		out = append(out, toEnrollmentResponse(r))
	}
	return out
}

func toCertResponse(c *types.DeviceCertificate) certResponse {
	resp := certResponse{
		ID:          c.ID,
		PeerID:      c.PeerID,
		WGPublicKey: c.WGPublicKey,
		Serial:      c.Serial,
		NotBefore:   c.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:    c.NotAfter.UTC().Format(time.RFC3339),
		Revoked:     c.Revoked,
	}
	if c.RevokedAt != nil {
		s := c.RevokedAt.UTC().Format(time.RFC3339)
		resp.RevokedAt = &s
	}
	return resp
}

func toCertResponseList(certs []*types.DeviceCertificate) []certResponse {
	out := make([]certResponse, 0, len(certs))
	for _, c := range certs {
		out = append(out, toCertResponse(c))
	}
	return out
}

func toCAResponse(c *types.TrustedCA) caResponse {
	return caResponse{
		ID:        c.ID,
		Name:      c.Name,
		CreatedAt: c.CreatedAt.UTC().Format(time.RFC3339),
		PEM:       c.PEM,
	}
}

func toCAResponseList(cas []*types.TrustedCA) []caResponse {
	out := make([]caResponse, 0, len(cas))
	for _, c := range cas {
		out = append(out, toCAResponse(c))
	}
	return out
}

// deviceAuthSettingsRequest is the request body for PUT /device-auth/settings.
// All fields are optional; omitted fields are left unchanged.
type deviceAuthSettingsRequest struct {
	Mode                      *string `json:"mode"`
	EnrollmentMode            *string `json:"enrollment_mode"`
	CAType                    *string `json:"ca_type"`
	CAConfig                  *string `json:"ca_config"`
	CertValidityDays          *int    `json:"cert_validity_days"`
	OCSPEnabled               *bool   `json:"ocsp_enabled"`
	FailOpenOnOCSPUnavailable *bool   `json:"fail_open_on_ocsp_unavailable"`
	InventoryType             *string `json:"inventory_type"`
	InventoryConfig           *string `json:"inventory_config"`
	// RequireInventoryCheck gates manual enrollment: when true, devices must be
	// found in the configured inventory before an enrollment request is accepted.
	RequireInventoryCheck *bool `json:"require_inventory_check"`
}

// deviceAuthSettingsResponse is the response body for GET|PUT /device-auth/settings.
type deviceAuthSettingsResponse struct {
	Mode                      string `json:"mode"`
	EnrollmentMode            string `json:"enrollment_mode"`
	CAType                    string `json:"ca_type"`
	CertValidityDays          int    `json:"cert_validity_days"`
	OCSPEnabled               bool   `json:"ocsp_enabled"`
	FailOpenOnOCSPUnavailable bool   `json:"fail_open_on_ocsp_unavailable"`
	InventoryType             string `json:"inventory_type"`
	RequireInventoryCheck     bool   `json:"require_inventory_check"`
}

// defaultDeviceAuthSettingsResponse returns sensible defaults for fresh accounts
// that have never saved device security settings.
func defaultDeviceAuthSettingsResponse() deviceAuthSettingsResponse {
	return deviceAuthSettingsResponse{
		Mode:             types.DeviceAuthModeDisabled,
		EnrollmentMode:   types.DeviceAuthEnrollmentManual,
		CAType:           types.DeviceAuthCATypeBuiltin,
		CertValidityDays: 365,
	}
}

func toDeviceAuthSettingsResponse(s *types.DeviceAuthSettings) deviceAuthSettingsResponse {
	mode := s.Mode
	if mode == "" {
		mode = types.DeviceAuthModeDisabled
	}
	enrollmentMode := s.EnrollmentMode
	if enrollmentMode == "" {
		enrollmentMode = types.DeviceAuthEnrollmentManual
	}
	caType := s.CAType
	if caType == "" {
		caType = types.DeviceAuthCATypeBuiltin
	}
	certValidityDays := s.CertValidityDays
	if certValidityDays == 0 {
		certValidityDays = 365
	}
	return deviceAuthSettingsResponse{
		Mode:                      mode,
		EnrollmentMode:            enrollmentMode,
		CAType:                    caType,
		CertValidityDays:          certValidityDays,
		OCSPEnabled:               s.OCSPEnabled,
		FailOpenOnOCSPUnavailable: s.FailOpenOnOCSPUnavailable,
		InventoryType:             s.InventoryType,
		RequireInventoryCheck:     s.RequireInventoryCheck,
		// CAConfig and InventoryConfig are intentionally omitted from the response
		// to avoid leaking sensitive credentials (client secrets, API keys, etc.).
	}
}
