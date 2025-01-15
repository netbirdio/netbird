package users

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/http/configs"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/management/server/types"
)

// patHandler is the nameserver group handler of the account
type patHandler struct {
	accountManager  server.AccountManager
	claimsExtractor *jwtclaims.ClaimsExtractor
}

func addUsersTokensEndpoint(accountManager server.AccountManager, authCfg configs.AuthCfg, router *mux.Router) {
	tokenHandler := newPATsHandler(accountManager, authCfg)
	router.HandleFunc("/users/{userId}/tokens", tokenHandler.getAllTokens).Methods("GET", "OPTIONS")
	router.HandleFunc("/users/{userId}/tokens", tokenHandler.createToken).Methods("POST", "OPTIONS")
	router.HandleFunc("/users/{userId}/tokens/{tokenId}", tokenHandler.getToken).Methods("GET", "OPTIONS")
	router.HandleFunc("/users/{userId}/tokens/{tokenId}", tokenHandler.deleteToken).Methods("DELETE", "OPTIONS")
}

// newPATsHandler creates a new patHandler HTTP handler
func newPATsHandler(accountManager server.AccountManager, authCfg configs.AuthCfg) *patHandler {
	return &patHandler{
		accountManager: accountManager,
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithAudience(authCfg.Audience),
			jwtclaims.WithUserIDClaim(authCfg.UserIDClaim),
		),
	}
}

// getAllTokens is HTTP GET handler that returns a list of all personal access tokens for the given user
func (h *patHandler) getAllTokens(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.accountManager.GetAccountIDFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	vars := mux.Vars(r)
	targetUserID := vars["userId"]
	if len(userID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid user ID"), w)
		return
	}

	pats, err := h.accountManager.GetAllPATs(r.Context(), accountID, userID, targetUserID)
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
func (h *patHandler) getToken(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.accountManager.GetAccountIDFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

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

	pat, err := h.accountManager.GetPAT(r.Context(), accountID, userID, targetUserID, tokenID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, toPATResponse(pat))
}

// createToken is HTTP POST handler that creates a personal access token for the given user
func (h *patHandler) createToken(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.accountManager.GetAccountIDFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	vars := mux.Vars(r)
	targetUserID := vars["userId"]
	if len(targetUserID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid user ID"), w)
		return
	}

	var req api.PostApiUsersUserIdTokensJSONRequestBody
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	pat, err := h.accountManager.CreatePAT(r.Context(), accountID, userID, targetUserID, req.Name, req.ExpiresIn)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, toPATGeneratedResponse(pat))
}

// deleteToken is HTTP DELETE handler that deletes a personal access token for the given user
func (h *patHandler) deleteToken(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.accountManager.GetAccountIDFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

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

	err = h.accountManager.DeletePAT(r.Context(), accountID, userID, targetUserID, tokenID)
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
