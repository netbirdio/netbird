package ca

import (
	"net/http"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	nbca "github.com/netbirdio/netbird/management/server/ca"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

type handler struct {
	caManager          *nbca.Manager
	accountManager     account.Manager
	permissionsManager permissions.Manager
}

// AddEndpoints registers the CA management REST endpoints.
func AddEndpoints(caManager *nbca.Manager, accountManager account.Manager, permissionsManager permissions.Manager, router *mux.Router) {
	h := newHandler(caManager, accountManager, permissionsManager)
	router.HandleFunc("/ca", h.listCAs).Methods("GET", "OPTIONS")
	router.HandleFunc("/ca", h.initCA).Methods("POST", "OPTIONS")
	router.HandleFunc("/ca/rotate", h.rotateCA).Methods("POST", "OPTIONS")
	router.HandleFunc("/ca/certificates", h.listIssuedCerts).Methods("GET", "OPTIONS")
	router.HandleFunc("/ca/certificates/{serialNumber}/revoke", h.revokeCert).Methods("POST", "OPTIONS")
	router.HandleFunc("/ca/{caId}", h.getCA).Methods("GET", "OPTIONS")
	router.HandleFunc("/ca/{caId}", h.deactivateCA).Methods("DELETE", "OPTIONS")
}

func newHandler(caManager *nbca.Manager, accountManager account.Manager, permissionsManager permissions.Manager) *handler {
	return &handler{
		caManager:          caManager,
		accountManager:     accountManager,
		permissionsManager: permissionsManager,
	}
}

func (h *handler) listCAs(w http.ResponseWriter, r *http.Request) {
	accountID, _, err := h.checkPermission(r, operations.Read)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	cas, err := h.caManager.GetActiveCACertificates(r.Context(), accountID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	resp := make([]api.CACertificateResponse, 0, len(cas))
	for _, c := range cas {
		resp = append(resp, toCACertificateResponse(c, false))
	}

	util.WriteJSONObject(r.Context(), w, resp)
}

func (h *handler) initCA(w http.ResponseWriter, r *http.Request) {
	accountID, userID, err := h.checkPermission(r, operations.Create)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	dnsDomain, err := h.getAccountDNSDomain(r, accountID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	caCert, err := h.caManager.InitForAccount(r.Context(), accountID, dnsDomain, nbca.CAOptions{})
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	h.accountManager.StoreEvent(r.Context(), userID, caCert.ID, accountID, activity.CertificateAuthorityCreated, nil)

	util.WriteJSONObject(r.Context(), w, toCACertificateResponse(caCert, false))
}

func (h *handler) getCA(w http.ResponseWriter, r *http.Request) {
	accountID, _, err := h.checkPermission(r, operations.Read)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	vars := mux.Vars(r)
	caID := vars["caId"]
	if caID == "" {
		util.WriteErrorResponse("CA ID is required", http.StatusBadRequest, w)
		return
	}

	caCert, err := h.caManager.GetCACertificate(r.Context(), accountID, caID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, toCACertificateResponse(caCert, true))
}

func (h *handler) deactivateCA(w http.ResponseWriter, r *http.Request) {
	accountID, userID, err := h.checkPermission(r, operations.Delete)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	vars := mux.Vars(r)
	caID := vars["caId"]
	if caID == "" {
		util.WriteErrorResponse("CA ID is required", http.StatusBadRequest, w)
		return
	}

	if err := h.caManager.DeactivateCA(r.Context(), accountID, caID); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	h.accountManager.StoreEvent(r.Context(), userID, caID, accountID, activity.CertificateAuthorityDeactivated, nil)

	util.WriteJSONObject(r.Context(), w, util.EmptyObject{})
}

func (h *handler) rotateCA(w http.ResponseWriter, r *http.Request) {
	accountID, userID, err := h.checkPermission(r, operations.Create)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	dnsDomain, err := h.getAccountDNSDomain(r, accountID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	caCert, err := h.caManager.RotateCA(r.Context(), accountID, dnsDomain, nbca.CAOptions{})
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	h.accountManager.StoreEvent(r.Context(), userID, caCert.ID, accountID, activity.CertificateAuthorityRotated, nil)

	util.WriteJSONObject(r.Context(), w, toCACertificateResponse(caCert, false))
}

func (h *handler) listIssuedCerts(w http.ResponseWriter, r *http.Request) {
	accountID, _, err := h.checkPermission(r, operations.Read)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	peerID := r.URL.Query().Get("peer_id")

	var certs []*nbca.IssuedCertificate
	if peerID != "" {
		certs, err = h.caManager.GetIssuedCertificatesByPeer(r.Context(), accountID, peerID)
	} else {
		certs, err = h.caManager.GetIssuedCertificates(r.Context(), accountID)
	}
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	resp := make([]api.IssuedCertificateResponse, 0, len(certs))
	for _, c := range certs {
		resp = append(resp, toIssuedCertificateResponse(c))
	}

	util.WriteJSONObject(r.Context(), w, resp)
}

func (h *handler) revokeCert(w http.ResponseWriter, r *http.Request) {
	accountID, userID, err := h.checkPermission(r, operations.Delete)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	vars := mux.Vars(r)
	serialNumber := vars["serialNumber"]
	if serialNumber == "" {
		util.WriteErrorResponse("serial number is required", http.StatusBadRequest, w)
		return
	}

	if err := h.caManager.RevokeCertificate(r.Context(), accountID, serialNumber); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	h.accountManager.StoreEvent(r.Context(), userID, serialNumber, accountID, activity.CertificateRevoked, nil)

	util.WriteJSONObject(r.Context(), w, util.EmptyObject{})
}

// checkPermission extracts user auth and validates permissions.
// Returns accountID and userID on success.
func (h *handler) checkPermission(r *http.Request, op operations.Operation) (string, string, error) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		return "", "", err
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId

	allowed, err := h.permissionsManager.ValidateUserPermissions(r.Context(), accountID, userID, modules.CertificateAuthority, op)
	if err != nil {
		return "", "", status.NewPermissionValidationError(err)
	}

	if !allowed {
		return "", "", status.NewPermissionDeniedError()
	}

	return accountID, userID, nil
}

// getAccountDNSDomain retrieves the DNS domain from account settings.
func (h *handler) getAccountDNSDomain(r *http.Request, accountID string) (string, error) {
	settings, err := h.accountManager.GetStore().GetAccountSettings(r.Context(), store.LockingStrengthNone, accountID)
	if err != nil {
		return "", err
	}

	if settings.DNSDomain == "" {
		return "", status.Errorf(status.PreconditionFailed, "account DNS domain is not configured")
	}

	return settings.DNSDomain, nil
}

func toCACertificateResponse(c *nbca.CACertificate, includePEM bool) api.CACertificateResponse {
	resp := api.CACertificateResponse{
		Id:          c.ID,
		Fingerprint: c.Fingerprint,
		NotBefore:   c.NotBefore.UTC(),
		NotAfter:    c.NotAfter.UTC(),
		IsActive:    c.IsActive,
		CreatedAt:   c.CreatedAt.UTC(),
	}
	if includePEM {
		resp.CertificatePem = &c.CertificatePEM
	}
	return resp
}

func toIssuedCertificateResponse(c *nbca.IssuedCertificate) api.IssuedCertificateResponse {
	dnsNames := c.DNSNames
	if dnsNames == nil {
		dnsNames = []string{}
	}
	return api.IssuedCertificateResponse{
		Id:           c.ID,
		PeerId:       c.PeerID,
		SerialNumber: c.SerialNumber,
		DnsNames:     dnsNames,
		HasWildcard:  c.HasWildcard,
		NotBefore:    c.NotBefore.UTC(),
		NotAfter:     c.NotAfter.UTC(),
		SigningType:  c.SigningType,
		Revoked:      c.Revoked,
		CreatedAt:    c.CreatedAt.UTC(),
	}
}
