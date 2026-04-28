// Package credentials implements the HTTP API surface for the
// per-account encrypted credential records used by the management
// server. Secrets are write-only via this surface — the plaintext value
// is accepted on POST and never returned on any read.
package credentials

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	credentialsmodel "github.com/netbirdio/netbird/management/internals/modules/credentials"
	"github.com/netbirdio/netbird/management/server/account"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

type handler struct {
	accountManager account.Manager
}

// AddEndpoints registers the /credentials routes on router.
func AddEndpoints(accountManager account.Manager, router *mux.Router) {
	h := &handler{accountManager: accountManager}
	router.HandleFunc("/credentials", h.list).Methods("GET", "OPTIONS")
	router.HandleFunc("/credentials", h.create).Methods("POST", "OPTIONS")
	router.HandleFunc("/credentials/{credentialId}", h.get).Methods("GET", "OPTIONS")
	router.HandleFunc("/credentials/{credentialId}", h.update).Methods("PUT", "OPTIONS")
	router.HandleFunc("/credentials/{credentialId}", h.delete).Methods("DELETE", "OPTIONS")
}

// list returns metadata for all credentials owned by the calling account.
func (h *handler) list(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		log.WithContext(r.Context()).Error(err)
		util.WriteError(r.Context(), err, w)
		return
	}
	accountID, userID := userAuth.AccountId, userAuth.UserId

	providerType := r.URL.Query().Get("provider_type")

	recs, err := h.accountManager.ListCredentials(r.Context(), accountID, userID, providerType)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	resp := make([]*api.Credential, 0, len(recs))
	for _, rec := range recs {
		resp = append(resp, toAPI(rec))
	}
	util.WriteJSONObject(r.Context(), w, resp)
}

// create stores a new credential.
func (h *handler) create(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	accountID, userID := userAuth.AccountId, userAuth.UserId

	var req api.CredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid request body: %v", err), w)
		return
	}

	rec, err := h.accountManager.CreateCredential(r.Context(), accountID, userID, req.ProviderType, req.Name, req.Secret)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, toAPI(rec))
}

// get returns metadata for a single credential.
func (h *handler) get(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	accountID, userID := userAuth.AccountId, userAuth.UserId

	ref := mux.Vars(r)["credentialId"]
	if ref == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "credential id is required"), w)
		return
	}

	rec, err := h.accountManager.GetCredentialMetadata(r.Context(), accountID, userID, ref)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, toAPI(rec))
}

// update overwrites the encrypted secret (and optionally provider type
// and name) for an existing credential. The ref is stable.
func (h *handler) update(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	accountID, userID := userAuth.AccountId, userAuth.UserId

	ref := mux.Vars(r)["credentialId"]
	if ref == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "credential id is required"), w)
		return
	}

	var req api.CredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid request body: %v", err), w)
		return
	}

	rec, err := h.accountManager.UpdateCredential(r.Context(), accountID, userID, ref, req.ProviderType, req.Name, req.Secret)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, toAPI(rec))
}

// delete removes a credential.
func (h *handler) delete(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	accountID, userID := userAuth.AccountId, userAuth.UserId

	ref := mux.Vars(r)["credentialId"]
	if ref == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "credential id is required"), w)
		return
	}

	if err := h.accountManager.DeleteCredential(r.Context(), accountID, userID, ref); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, struct{}{})
}

// toAPI maps the internal Credential to the API response type.
// Importantly, the EncryptedSecret field is never copied onto the wire —
// the API type doesn't have a secret field, so this mapping is the
// enforcement boundary for the "secrets never leave on responses"
// invariant.
func toAPI(rec *credentialsmodel.Credential) *api.Credential {
	if rec == nil {
		return nil
	}
	return &api.Credential{
		Id:           rec.ID,
		ProviderType: rec.ProviderType,
		Name:         rec.Name,
		CreatedAt:    rec.CreatedAt,
	}
}
