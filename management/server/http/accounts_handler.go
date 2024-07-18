package http

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/status"
)

// AccountsHandler is a handler that handles the server.Account HTTP endpoints
type AccountsHandler struct {
	accountManager  server.AccountManager
	claimsExtractor *jwtclaims.ClaimsExtractor
}

// NewAccountsHandler creates a new AccountsHandler HTTP handler
func NewAccountsHandler(accountManager server.AccountManager, authCfg AuthCfg) *AccountsHandler {
	return &AccountsHandler{
		accountManager: accountManager,
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithAudience(authCfg.Audience),
			jwtclaims.WithUserIDClaim(authCfg.UserIDClaim),
		),
	}
}

// GetAllAccounts is HTTP GET handler that returns a list of accounts. Effectively returns just a single account.
func (h *AccountsHandler) GetAllAccounts(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	account, user, err := h.accountManager.GetAccountFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	if !(user.HasAdminPower() || user.IsServiceUser) {
		util.WriteError(r.Context(), status.Errorf(status.PermissionDenied, "the user has no permission to access account data"), w)
		return
	}

	resp := toAccountResponse(account)
	util.WriteJSONObject(r.Context(), w, []*api.Account{resp})
}

// UpdateAccount is HTTP PUT handler that updates the provided account. Updates only account settings (server.Settings)
func (h *AccountsHandler) UpdateAccount(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	_, user, err := h.accountManager.GetAccountFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	vars := mux.Vars(r)
	accountID := vars["accountId"]
	if len(accountID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid accountID ID"), w)
		return
	}

	var req api.PutApiAccountsAccountIdJSONRequestBody
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	settings := &server.Settings{
		PeerLoginExpirationEnabled: req.Settings.PeerLoginExpirationEnabled,
		PeerLoginExpiration:        time.Duration(float64(time.Second.Nanoseconds()) * float64(req.Settings.PeerLoginExpiration)),
		RegularUsersViewBlocked:    req.Settings.RegularUsersViewBlocked,

		PeerInactivityExpirationEnabled: req.Settings.PeerInactivityExpirationEnabled,
		PeerInactivityExpiration:        time.Duration(float64(time.Second.Nanoseconds()) * float64(req.Settings.PeerInactivityExpiration)),
	}

	if req.Settings.Extra != nil {
		settings.Extra = &account.ExtraSettings{PeerApprovalEnabled: *req.Settings.Extra.PeerApprovalEnabled}
	}

	if req.Settings.JwtGroupsEnabled != nil {
		settings.JWTGroupsEnabled = *req.Settings.JwtGroupsEnabled
	}
	if req.Settings.GroupsPropagationEnabled != nil {
		settings.GroupsPropagationEnabled = *req.Settings.GroupsPropagationEnabled
	}
	if req.Settings.JwtGroupsClaimName != nil {
		settings.JWTGroupsClaimName = *req.Settings.JwtGroupsClaimName
	}
	if req.Settings.JwtAllowGroups != nil {
		settings.JWTAllowGroups = *req.Settings.JwtAllowGroups
	}

	updatedAccount, err := h.accountManager.UpdateAccountSettings(r.Context(), accountID, user.Id, settings)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	resp := toAccountResponse(updatedAccount)

	util.WriteJSONObject(r.Context(), w, &resp)
}

// DeleteAccount is a HTTP DELETE handler to delete an account
func (h *AccountsHandler) DeleteAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		util.WriteErrorResponse("wrong HTTP method", http.StatusMethodNotAllowed, w)
		return
	}

	claims := h.claimsExtractor.FromRequestContext(r)
	vars := mux.Vars(r)
	targetAccountID := vars["accountId"]
	if len(targetAccountID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid account ID"), w)
		return
	}

	err := h.accountManager.DeleteAccount(r.Context(), targetAccountID, claims.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, emptyObject{})
}

func toAccountResponse(account *server.Account) *api.Account {
	jwtAllowGroups := account.Settings.JWTAllowGroups
	if jwtAllowGroups == nil {
		jwtAllowGroups = []string{}
	}

	settings := api.AccountSettings{
		PeerLoginExpiration:        int(account.Settings.PeerLoginExpiration.Seconds()),
		PeerLoginExpirationEnabled: account.Settings.PeerLoginExpirationEnabled,
		GroupsPropagationEnabled:   &account.Settings.GroupsPropagationEnabled,
		JwtGroupsEnabled:           &account.Settings.JWTGroupsEnabled,
		JwtGroupsClaimName:         &account.Settings.JWTGroupsClaimName,
		JwtAllowGroups:             &jwtAllowGroups,
		RegularUsersViewBlocked:    account.Settings.RegularUsersViewBlocked,
	}

	if account.Settings.Extra != nil {
		settings.Extra = &api.AccountExtraSettings{PeerApprovalEnabled: &account.Settings.Extra.PeerApprovalEnabled}
	}

	return &api.Account{
		Id:       account.Id,
		Settings: settings,
	}
}
