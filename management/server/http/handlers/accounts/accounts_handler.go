package accounts

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/account"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/management/server/types"
)

// handler is a handler that handles the server.Account HTTP endpoints
type handler struct {
	accountManager server.AccountManager
}

func AddEndpoints(accountManager server.AccountManager, router *mux.Router) {
	accountsHandler := newHandler(accountManager)
	router.HandleFunc("/accounts/{accountId}", accountsHandler.updateAccount).Methods("PUT", "OPTIONS")
	router.HandleFunc("/accounts/{accountId}", accountsHandler.deleteAccount).Methods("DELETE", "OPTIONS")
	router.HandleFunc("/accounts", accountsHandler.getAllAccounts).Methods("GET", "OPTIONS")
}

// newHandler creates a new handler HTTP handler
func newHandler(accountManager server.AccountManager) *handler {
	return &handler{
		accountManager: accountManager,
	}
}

// getAllAccounts is HTTP GET handler that returns a list of accounts. Effectively returns just a single account.
func (h *handler) getAllAccounts(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId

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
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	_, userID := userAuth.AccountId, userAuth.UserId

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
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	vars := mux.Vars(r)
	targetAccountID := vars["accountId"]
	if len(targetAccountID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid account ID"), w)
		return
	}

	err = h.accountManager.DeleteAccount(r.Context(), targetAccountID, userAuth.UserId)
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
