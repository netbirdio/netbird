package proxytoken

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

type handler struct {
	store              store.Store
	permissionsManager permissions.Manager
}

func RegisterEndpoints(s store.Store, permissionsManager permissions.Manager, router *mux.Router) {
	h := &handler{store: s, permissionsManager: permissionsManager}
	router.HandleFunc("/reverse-proxies/proxy-tokens", h.listTokens).Methods("GET", "OPTIONS")
	router.HandleFunc("/reverse-proxies/proxy-tokens", h.createToken).Methods("POST", "OPTIONS")
	router.HandleFunc("/reverse-proxies/proxy-tokens/{tokenId}", h.revokeToken).Methods("DELETE", "OPTIONS")
}

func (h *handler) createToken(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	ok, err := h.permissionsManager.ValidateUserPermissions(r.Context(), userAuth.AccountId, userAuth.UserId, modules.Services, operations.Create)
	if err != nil {
		util.WriteErrorResponse("failed to validate permissions", http.StatusInternalServerError, w)
		return
	}
	if !ok {
		util.WriteErrorResponse("permission denied", http.StatusForbidden, w)
		return
	}

	var req api.ProxyTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	if req.Name == "" || len(req.Name) > 255 {
		util.WriteErrorResponse("name is required and must be at most 255 characters", http.StatusBadRequest, w)
		return
	}

	var expiresIn time.Duration
	if req.ExpiresIn != nil {
		if *req.ExpiresIn < 0 {
			util.WriteErrorResponse("expires_in must be non-negative", http.StatusBadRequest, w)
			return
		}
		if *req.ExpiresIn > 0 {
			expiresIn = time.Duration(*req.ExpiresIn) * time.Second
		}
	}

	accountID := userAuth.AccountId
	generated, err := types.CreateNewProxyAccessToken(req.Name, expiresIn, &accountID, userAuth.UserId)
	if err != nil {
		util.WriteErrorResponse("failed to generate token", http.StatusInternalServerError, w)
		return
	}

	if err := h.store.SaveProxyAccessToken(r.Context(), &generated.ProxyAccessToken); err != nil {
		util.WriteErrorResponse("failed to save token", http.StatusInternalServerError, w)
		return
	}

	resp := toProxyTokenCreatedResponse(generated)
	util.WriteJSONObject(r.Context(), w, resp)
}

func (h *handler) listTokens(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	ok, err := h.permissionsManager.ValidateUserPermissions(r.Context(), userAuth.AccountId, userAuth.UserId, modules.Services, operations.Read)
	if err != nil {
		util.WriteErrorResponse("failed to validate permissions", http.StatusInternalServerError, w)
		return
	}
	if !ok {
		util.WriteErrorResponse("permission denied", http.StatusForbidden, w)
		return
	}

	tokens, err := h.store.GetProxyAccessTokensByAccountID(r.Context(), store.LockingStrengthNone, userAuth.AccountId)
	if err != nil {
		util.WriteErrorResponse("failed to list tokens", http.StatusInternalServerError, w)
		return
	}

	resp := make([]api.ProxyToken, 0, len(tokens))
	for _, token := range tokens {
		resp = append(resp, toProxyTokenResponse(token))
	}

	util.WriteJSONObject(r.Context(), w, resp)
}

func (h *handler) revokeToken(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	ok, err := h.permissionsManager.ValidateUserPermissions(r.Context(), userAuth.AccountId, userAuth.UserId, modules.Services, operations.Delete)
	if err != nil {
		util.WriteErrorResponse("failed to validate permissions", http.StatusInternalServerError, w)
		return
	}
	if !ok {
		util.WriteErrorResponse("permission denied", http.StatusForbidden, w)
		return
	}

	tokenID := mux.Vars(r)["tokenId"]
	if tokenID == "" {
		util.WriteErrorResponse("token ID is required", http.StatusBadRequest, w)
		return
	}

	token, err := h.store.GetProxyAccessTokenByID(r.Context(), store.LockingStrengthNone, tokenID)
	if err != nil {
		if s, ok := status.FromError(err); ok && s.ErrorType == status.NotFound {
			util.WriteErrorResponse("token not found", http.StatusNotFound, w)
		} else {
			util.WriteErrorResponse("failed to retrieve token", http.StatusInternalServerError, w)
		}
		return
	}

	if token.AccountID == nil || *token.AccountID != userAuth.AccountId {
		util.WriteErrorResponse("token not found", http.StatusNotFound, w)
		return
	}

	if err := h.store.RevokeProxyAccessToken(r.Context(), tokenID); err != nil {
		util.WriteErrorResponse("failed to revoke token", http.StatusInternalServerError, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, util.EmptyObject{})
}

func toProxyTokenResponse(token *types.ProxyAccessToken) api.ProxyToken {
	resp := api.ProxyToken{
		Id:      token.ID,
		Name:    token.Name,
		Revoked: token.Revoked,
	}
	if !token.CreatedAt.IsZero() {
		resp.CreatedAt = token.CreatedAt
	}
	if token.ExpiresAt != nil {
		resp.ExpiresAt = token.ExpiresAt
	}
	if token.LastUsed != nil {
		resp.LastUsed = token.LastUsed
	}
	return resp
}

func toProxyTokenCreatedResponse(generated *types.ProxyAccessTokenGenerated) api.ProxyTokenCreated {
	base := toProxyTokenResponse(&generated.ProxyAccessToken)
	plainToken := string(generated.PlainToken)
	return api.ProxyTokenCreated{
		Id:         base.Id,
		Name:       base.Name,
		CreatedAt:  base.CreatedAt,
		ExpiresAt:  base.ExpiresAt,
		LastUsed:   base.LastUsed,
		Revoked:    base.Revoked,
		PlainToken: plainToken,
	}
}
