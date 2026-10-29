package idp

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/server/account"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

// handler handles identity provider HTTP endpoints
type handler struct {
	accountManager account.Manager
}

// AddEndpoints registers identity provider endpoints
func AddEndpoints(accountManager account.Manager, router *mux.Router) {
	h := newHandler(accountManager)
	router.HandleFunc("/identity-providers", h.getAllIdentityProviders).Methods("GET", "OPTIONS")
	router.HandleFunc("/identity-providers", h.createIdentityProvider).Methods("POST", "OPTIONS")
	router.HandleFunc("/identity-providers/{idpId}", h.getIdentityProvider).Methods("GET", "OPTIONS")
	router.HandleFunc("/identity-providers/{idpId}", h.updateIdentityProvider).Methods("PUT", "OPTIONS")
	router.HandleFunc("/identity-providers/{idpId}", h.deleteIdentityProvider).Methods("DELETE", "OPTIONS")
}

func newHandler(accountManager account.Manager) *handler {
	return &handler{
		accountManager: accountManager,
	}
}

// getAllIdentityProviders returns all identity providers for the account
func (h *handler) getAllIdentityProviders(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId

	providers, err := h.accountManager.GetIdentityProviders(r.Context(), accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	response := make([]api.IdentityProvider, 0, len(providers))
	for _, p := range providers {
		response = append(response, toAPIResponse(p))
	}

	util.WriteJSONObject(r.Context(), w, response)
}

// getIdentityProvider returns a specific identity provider
func (h *handler) getIdentityProvider(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId

	vars := mux.Vars(r)
	idpID := vars["idpId"]
	if idpID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "identity provider ID is required"), w)
		return
	}

	provider, err := h.accountManager.GetIdentityProvider(r.Context(), accountID, idpID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, toAPIResponse(provider))
}

// createIdentityProvider creates a new identity provider
func (h *handler) createIdentityProvider(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId

	var req api.IdentityProviderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	idp := fromAPIRequest(&req)

	created, err := h.accountManager.CreateIdentityProvider(r.Context(), accountID, userID, idp)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, toAPIResponse(created))
}

// updateIdentityProvider updates an existing identity provider
func (h *handler) updateIdentityProvider(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId

	vars := mux.Vars(r)
	idpID := vars["idpId"]
	if idpID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "identity provider ID is required"), w)
		return
	}

	var req api.IdentityProviderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	idp := fromAPIRequest(&req)

	updated, err := h.accountManager.UpdateIdentityProvider(r.Context(), accountID, idpID, userID, idp)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, toAPIResponse(updated))
}

// deleteIdentityProvider deletes an identity provider
func (h *handler) deleteIdentityProvider(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId

	vars := mux.Vars(r)
	idpID := vars["idpId"]
	if idpID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "identity provider ID is required"), w)
		return
	}

	if err := h.accountManager.DeleteIdentityProvider(r.Context(), accountID, idpID, userID); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, util.EmptyObject{})
}

func toAPIResponse(idp *types.IdentityProvider) api.IdentityProvider {
	resp := api.IdentityProvider{
		Type:     api.IdentityProviderType(idp.Type),
		Name:     idp.Name,
		Issuer:   idp.Issuer,
		ClientId: idp.ClientID,
	}
	if idp.ID != "" {
		resp.Id = &idp.ID
	}
	// Note: ClientSecret is never returned in responses for security
	return resp
}

func fromAPIRequest(req *api.IdentityProviderRequest) *types.IdentityProvider {
	return &types.IdentityProvider{
		Type:         types.IdentityProviderType(req.Type),
		Name:         req.Name,
		Issuer:       req.Issuer,
		ClientID:     req.ClientId,
		ClientSecret: req.ClientSecret,
	}
}
