package http

import (
	"encoding/json"
	"net/http"

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

func NewPATsHandler(accountManager server.AccountManager, authCfg AuthCfg) *PATHandler {
	return &PATHandler{
		accountManager: accountManager,
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithAudience(authCfg.Audience),
			jwtclaims.WithUserIDClaim(authCfg.UserIDClaim),
		),
	}
}

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
	if userID != user.Id {
		util.WriteErrorResponse("User not authorized to get tokens", http.StatusUnauthorized, w)
		return
	}

	var pats []*api.PersonalAccessToken
	for _, pat := range account.Users[userID].PATs {
		pats = append(pats, toPATResponse(pat))
	}

	util.WriteJSONObject(w, pats)
}

func (h *PATHandler) GetToken(w http.ResponseWriter, r *http.Request) {
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
	if userID != user.Id {
		util.WriteErrorResponse("User not authorized to get token", http.StatusUnauthorized, w)
		return
	}

	tokenID := vars["tokenId"]
	if len(tokenID) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid token ID"), w)
		return
	}

	user = account.Users[userID]
	if user == nil {
		util.WriteError(status.Errorf(status.NotFound, "user not found"), w)
		return
	}

	pat := user.PATs[tokenID]
	if pat == nil {
		util.WriteError(status.Errorf(status.NotFound, "PAT not found"), w)
		return
	}

	util.WriteJSONObject(w, toPATResponse(pat))
}

func (h *PATHandler) CreateToken(w http.ResponseWriter, r *http.Request) {
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
	if userID != user.Id {
		util.WriteErrorResponse("User not authorized to create token", http.StatusUnauthorized, w)
		return
	}

	var req api.PostApiUsersUserIdTokensJSONRequestBody
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	if req.Name == "" {
		util.WriteErrorResponse("name can't be empty", http.StatusBadRequest, w)
		return
	}

	if req.ExpiresIn < 1 || req.ExpiresIn > 365 {
		util.WriteErrorResponse("expiration has to be between 1 and 365", http.StatusBadRequest, w)
		return
	}

	pat, err := server.CreateNewPAT(req.Name, req.ExpiresIn, user.Id)
	err = h.accountManager.AddPATToUser(account.Id, userID, &pat.PersonalAccessToken)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	util.WriteJSONObject(w, toPATGeneratedResponse(pat))
}

func (h *PATHandler) DeleteToken(w http.ResponseWriter, r *http.Request) {
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
	if userID != user.Id {
		util.WriteErrorResponse("User not authorized to delete token", http.StatusUnauthorized, w)
		return
	}

	tokenID := vars["tokenId"]
	if len(tokenID) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid token ID"), w)
		return
	}

	err = h.accountManager.DeletePAT(account.Id, userID, tokenID)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	util.WriteJSONObject(w, "")
}

func toPATResponse(pat *server.PersonalAccessToken) *api.PersonalAccessToken {
	return &api.PersonalAccessToken{
		CreatedAt:      pat.CreatedAt,
		CreatedBy:      pat.CreatedBy,
		Name:           pat.Name,
		ExpirationDate: pat.ExpirationDate,
		Id:             pat.ID,
		LastUsed:       pat.LastUsed,
	}
}

func toPATGeneratedResponse(pat *server.PersonalAccessTokenGenerated) *api.PersonalAccessTokenGenerated {
	return &api.PersonalAccessTokenGenerated{
		PlainToken:          pat.PlainToken,
		PersonalAccessToken: *toPATResponse(&pat.PersonalAccessToken),
	}
}
