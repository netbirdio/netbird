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
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	if !user.IsAdmin() {
		util.WriteError(status.Errorf(status.PermissionDenied, "the user has no permission to access account data"), w)
		return
	}

	resp := toAccountResponse(account)
	util.WriteJSONObject(w, []*api.Account{resp})
}

// UpdateAccount is HTTP PUT handler that updates the provided account. Updates only account settings (server.Settings)
func (h *AccountsHandler) UpdateAccount(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	_, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	vars := mux.Vars(r)
	accountID := vars["accountId"]
	if len(accountID) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid accountID ID"), w)
		return
	}

	var req api.PutApiAccountsAccountIdJSONBody
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	updatedAccount, err := h.accountManager.UpdateAccountSettings(accountID, user.Id, &server.Settings{
		PeerLoginExpirationEnabled: req.Settings.PeerLoginExpirationEnabled,
		PeerLoginExpiration:        time.Duration(float64(time.Second.Nanoseconds()) * float64(req.Settings.PeerLoginExpiration)),
	})

	if err != nil {
		util.WriteError(err, w)
		return
	}

	resp := toAccountResponse(updatedAccount)

	util.WriteJSONObject(w, &resp)
}

func toAccountResponse(account *server.Account) *api.Account {
	return &api.Account{
		Id: account.Id,
		Settings: api.AccountSettings{
			PeerLoginExpiration:        int(account.Settings.PeerLoginExpiration.Seconds()),
			PeerLoginExpirationEnabled: account.Settings.PeerLoginExpirationEnabled,
		},
	}
}
