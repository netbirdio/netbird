package http

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/status"
)

// PATHandler is the nameserver group handler of the account
type PATHandler struct {
	accountManager  server.AccountManager
	claimsExtractor *jwtclaims.ClaimsExtractor
}

// NewPATsHandler creates a new PATHandler HTTP handler
func NewPATsHandler(accountManager server.AccountManager, authCfg AuthCfg) *PATHandler {
	return &PATHandler{
		accountManager: accountManager,
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithAudience(authCfg.Audience),
			jwtclaims.WithUserIDClaim(authCfg.UserIDClaim),
		),
	}
}

// GetAllTokens is HTTP GET handler that returns a list of all personal access tokens for the given user
func (h *PATHandler) GetAllTokens(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	vars := mux.Vars(r)
	userID := vars["userId"]
	if len(userID) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid user ID"), w)
		return
	}

	pats, err := h.accountManager.GetAllPATs(account.Id, user.Id, userID)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	var patResponse []*api.PersonalAccessToken
	for _, pat := range pats {
		patResponse = append(patResponse, toPATResponse(pat))
	}

	util.WriteJSONObject(w, patResponse)
}

// GetToken is HTTP GET handler that returns a personal access token for the given user
func (h *PATHandler) GetToken(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	vars := mux.Vars(r)
	targetUserID := vars["userId"]
	if len(targetUserID) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid user ID"), w)
		return
	}

	tokenID := vars["tokenId"]
	if len(tokenID) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid token ID"), w)
		return
	}

	pat, err := h.accountManager.GetPAT(account.Id, user.Id, targetUserID, tokenID)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	util.WriteJSONObject(w, toPATResponse(pat))
}

// CreateToken is HTTP POST handler that creates a personal access token for the given user
func (h *PATHandler) CreateToken(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	vars := mux.Vars(r)
	targetUserID := vars["userId"]
	if len(targetUserID) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid user ID"), w)
		return
	}

	var req api.PostApiUsersUserIdTokensJSONRequestBody
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	pat, err := h.accountManager.CreatePAT(account.Id, user.Id, targetUserID, req.Name, req.ExpiresIn)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	util.WriteJSONObject(w, toPATGeneratedResponse(pat))
}

// DeleteToken is HTTP DELETE handler that deletes a personal access token for the given user
func (h *PATHandler) DeleteToken(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	vars := mux.Vars(r)
	targetUserID := vars["userId"]
	if len(targetUserID) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid user ID"), w)
		return
	}

	tokenID := vars["tokenId"]
	if len(tokenID) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid token ID"), w)
		return
	}

	err = h.accountManager.DeletePAT(account.Id, user.Id, targetUserID, tokenID)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	util.WriteJSONObject(w, emptyObject{})
}

func toPATResponse(pat *server.PersonalAccessToken) *api.PersonalAccessToken {
	var lastUsed *time.Time
	if !pat.LastUsed.IsZero() {
		lastUsed = &pat.LastUsed
	}
	return &api.PersonalAccessToken{
		CreatedAt:      pat.CreatedAt,
		CreatedBy:      pat.CreatedBy,
		Name:           pat.Name,
		ExpirationDate: pat.ExpirationDate,
		Id:             pat.ID,
		LastUsed:       lastUsed,
	}
}

func toPATGeneratedResponse(pat *server.PersonalAccessTokenGenerated) *api.PersonalAccessTokenGenerated {
	return &api.PersonalAccessTokenGenerated{
		PlainToken:          pat.PlainToken,
		PersonalAccessToken: *toPATResponse(&pat.PersonalAccessToken),
	}
}
