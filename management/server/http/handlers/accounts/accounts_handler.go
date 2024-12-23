package accounts

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/http/configs"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/management/server/types"
)

// handler is a handler that handles the server.Account HTTP endpoints
type handler struct {
	accountManager  server.AccountManager
	claimsExtractor *jwtclaims.ClaimsExtractor
}

func AddEndpoints(accountManager server.AccountManager, authCfg configs.AuthCfg, router *mux.Router) {
	accountsHandler := newHandler(accountManager, authCfg)
	router.HandleFunc("/accounts/{accountId}", accountsHandler.updateAccount).Methods("PUT", "OPTIONS")
	router.HandleFunc("/accounts/{accountId}", accountsHandler.deleteAccount).Methods("DELETE", "OPTIONS")
	router.HandleFunc("/accounts", accountsHandler.getAllAccounts).Methods("GET", "OPTIONS")
}

// newHandler creates a new handler HTTP handler
func newHandler(accountManager server.AccountManager, authCfg configs.AuthCfg) *handler {
	return &handler{
		accountManager: accountManager,
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithAudience(authCfg.Audience),
			jwtclaims.WithUserIDClaim(authCfg.UserIDClaim),
		),
	}
}

// getAllAccounts is HTTP GET handler that returns a list of accounts. Effectively returns just a single account.
func (h *handler) getAllAccounts(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.accountManager.GetAccountIDFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	settings, err := h.accountManager.GetAccountSettings(r.Context(), accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	resp := toAccountResponse(accountID, settings)
	util.WriteJSONObject(r.Context(), w, []*api.Account{resp})
}

// updateAccount is HTTP PUT handler that updates the provided account. Updates only account settings (server.Settings)
func (h *handler) updateAccount(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	_, userID, err := h.accountManager.GetAccountIDFromToken(r.Context(), claims)
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

	settings := &types.Settings{
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
	if req.Settings.RoutingPeerDnsResolutionEnabled != nil {
		settings.RoutingPeerDNSResolutionEnabled = *req.Settings.RoutingPeerDnsResolutionEnabled
	}

	updatedAccount, err := h.accountManager.UpdateAccountSettings(r.Context(), accountID, userID, settings)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	resp := toAccountResponse(updatedAccount.Id, updatedAccount.Settings)

	util.WriteJSONObject(r.Context(), w, &resp)
}

// deleteAccount is a HTTP DELETE handler to delete an account
func (h *handler) deleteAccount(w http.ResponseWriter, r *http.Request) {
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

	util.WriteJSONObject(r.Context(), w, util.EmptyObject{})
}

func toAccountResponse(accountID string, settings *types.Settings) *api.Account {
	jwtAllowGroups := settings.JWTAllowGroups
	if jwtAllowGroups == nil {
		jwtAllowGroups = []string{}
	}

	apiSettings := api.AccountSettings{
		PeerLoginExpiration:             int(settings.PeerLoginExpiration.Seconds()),
		PeerLoginExpirationEnabled:      settings.PeerLoginExpirationEnabled,
		PeerInactivityExpiration:        int(settings.PeerInactivityExpiration.Seconds()),
		PeerInactivityExpirationEnabled: settings.PeerInactivityExpirationEnabled,
		GroupsPropagationEnabled:        &settings.GroupsPropagationEnabled,
		JwtGroupsEnabled:                &settings.JWTGroupsEnabled,
		JwtGroupsClaimName:              &settings.JWTGroupsClaimName,
		JwtAllowGroups:                  &jwtAllowGroups,
		RegularUsersViewBlocked:         settings.RegularUsersViewBlocked,
		RoutingPeerDnsResolutionEnabled: &settings.RoutingPeerDNSResolutionEnabled,
	}

	if settings.Extra != nil {
		apiSettings.Extra = &api.AccountExtraSettings{PeerApprovalEnabled: &settings.Extra.PeerApprovalEnabled}
	}

	return &api.Account{
		Id:       accountID,
		Settings: apiSettings,
	}
}
