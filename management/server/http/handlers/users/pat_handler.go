package users

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/internals/modules/permissions"
	"github.com/netbirdio/netbird/management/internals/modules/permissions/modules"
	"github.com/netbirdio/netbird/management/internals/modules/permissions/operations"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

// patHandler is the nameserver group handler of the account
type patHandler struct {
	accountManager account.Manager
}

func addUsersTokensEndpoint(accountManager account.Manager, router *mux.Router, permissionsManager permissions.Manager) {
	tokenHandler := newPATsHandler(accountManager)
	router.HandleFunc("/users/{userId}/tokens", permissionsManager.WithPermission(modules.Pats, operations.Read, tokenHandler.getAllTokens)).Methods("GET", "OPTIONS")
	router.HandleFunc("/users/{userId}/tokens", permissionsManager.WithPermission(modules.Pats, operations.Create, tokenHandler.createToken)).Methods("POST", "OPTIONS")
	router.HandleFunc("/users/{userId}/tokens/{tokenId}", permissionsManager.WithPermission(modules.Pats, operations.Read, tokenHandler.getToken)).Methods("GET", "OPTIONS")
	router.HandleFunc("/users/{userId}/tokens/{tokenId}", permissionsManager.WithPermission(modules.Pats, operations.Delete, tokenHandler.deleteToken)).Methods("DELETE", "OPTIONS")
}

// newPATsHandler creates a new patHandler HTTP handler
func newPATsHandler(accountManager account.Manager) *patHandler {
	return &patHandler{
		accountManager: accountManager,
	}
}

// getAllTokens is HTTP GET handler that returns a list of all personal access tokens for the given user
func (h *patHandler) getAllTokens(w http.ResponseWriter, r *http.Request, userAuth *auth.UserAuth) {
	vars := mux.Vars(r)
	targetUserID := vars["userId"]
	if len(targetUserID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid user ID"), w)
		return
	}

	pats, err := h.accountManager.GetAllPATs(r.Context(), userAuth.AccountId, userAuth.UserId, targetUserID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	var patResponse []*api.PersonalAccessToken
	for _, pat := range pats {
		patResponse = append(patResponse, toPATResponse(pat))
	}

	util.WriteJSONObject(r.Context(), w, patResponse)
}

// getToken is HTTP GET handler that returns a personal access token for the given user
func (h *patHandler) getToken(w http.ResponseWriter, r *http.Request, userAuth *auth.UserAuth) {
	vars := mux.Vars(r)
	targetUserID := vars["userId"]
	if len(targetUserID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid user ID"), w)
		return
	}

	tokenID := vars["tokenId"]
	if len(tokenID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid token ID"), w)
		return
	}

	pat, err := h.accountManager.GetPAT(r.Context(), userAuth.AccountId, userAuth.UserId, targetUserID, tokenID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, toPATResponse(pat))
}

// createToken is HTTP POST handler that creates a personal access token for the given user
func (h *patHandler) createToken(w http.ResponseWriter, r *http.Request, userAuth *auth.UserAuth) {
	vars := mux.Vars(r)
	targetUserID := vars["userId"]
	if len(targetUserID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid user ID"), w)
		return
	}

	var req api.PostApiUsersUserIdTokensJSONRequestBody
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	pat, err := h.accountManager.CreatePAT(r.Context(), userAuth.AccountId, userAuth.UserId, targetUserID, req.Name, req.ExpiresIn)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, toPATGeneratedResponse(pat))
}

// deleteToken is HTTP DELETE handler that deletes a personal access token for the given user
func (h *patHandler) deleteToken(w http.ResponseWriter, r *http.Request, userAuth *auth.UserAuth) {
	vars := mux.Vars(r)
	targetUserID := vars["userId"]
	if len(targetUserID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid user ID"), w)
		return
	}

	tokenID := vars["tokenId"]
	if len(tokenID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid token ID"), w)
		return
	}

	err := h.accountManager.DeletePAT(r.Context(), userAuth.AccountId, userAuth.UserId, targetUserID, tokenID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, util.EmptyObject{})
}

func toPATResponse(pat *types.PersonalAccessToken) *api.PersonalAccessToken {
	return &api.PersonalAccessToken{
		CreatedAt:      pat.CreatedAt,
		CreatedBy:      pat.CreatedBy,
		Name:           pat.Name,
		ExpirationDate: pat.GetExpirationDate(),
		Id:             pat.ID,
		LastUsed:       pat.LastUsed,
	}
}

func toPATGeneratedResponse(pat *types.PersonalAccessTokenGenerated) *api.PersonalAccessTokenGenerated {
	return &api.PersonalAccessTokenGenerated{
		PlainToken:          pat.PlainToken,
		PersonalAccessToken: *toPATResponse(&pat.PersonalAccessToken),
	}
}
