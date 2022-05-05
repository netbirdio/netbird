package handler

import (
	"fmt"
	"net/http"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
)

type UserHandler struct {
	accountManager server.AccountManager
	authAudience   string
	jwtExtractor   jwtclaims.ClaimsExtractor
}

type UserResponse struct {
	Email string
	Role  string
}

func NewUserHandler(accountManager server.AccountManager, authAudience string) *UserHandler {
	return &UserHandler{
		accountManager: accountManager,
		authAudience:   authAudience,
		jwtExtractor:   *jwtclaims.NewClaimsExtractor(nil),
	}
}

func (u *UserHandler) getAccountId(r *http.Request) (*server.Account, error) {
	jwtClaims := u.jwtExtractor.ExtractClaimsFromRequestContext(r, u.authAudience)

	account, err := u.accountManager.GetAccountWithAuthorizationClaims(jwtClaims)
	if err != nil {
		return nil, fmt.Errorf("failed getting account of a user %s: %v", jwtClaims.UserId, err)
	}

	return account, nil
}

// GetUsers returns a list of users of the account this user belongs to.
// It also gathers additional user data (like email and name) from the IDP manager.
func (u *UserHandler) GetUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "", http.StatusBadRequest)
	}

	account, err := u.getAccountId(r)
	if err != nil {
		log.Error(err)
	}

	data, err := u.accountManager.GetUsersFromAccount(account.Id)
	if err != nil {
		log.Error(err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	writeJSONObject(w, data)
}
