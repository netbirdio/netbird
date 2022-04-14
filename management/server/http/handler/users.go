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
	Id   string
	Role string
}

func NewUserHandler(accountManager server.AccountManager, authAudience string) *UserHandler {
	return &UserHandler{
		accountManager: accountManager,
		authAudience:   authAudience,
		jwtExtractor:   *jwtclaims.NewClaimsExtractor(nil),
	}
}

func (u *UserHandler) getUserIds(r *http.Request) (map[string]*server.User, error) {
	jwtClaims := u.jwtExtractor.ExtractClaimsFromRequestContext(r, u.authAudience)

	account, err := u.accountManager.GetAccountWithAuthorizationClaims(jwtClaims)
	if err != nil {
		return nil, fmt.Errorf("failed getting account of a user %s: %v", jwtClaims.UserId, err)
	}

	return account.Users, nil
}

// handle more user details in idp
// we first need to save more details about users in the store
func (u *UserHandler) GetUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "", http.StatusBadRequest)
	}
	userIDs, err := u.getUserIds(r)
	if err != nil {
		log.Error(err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	respBody := []*UserResponse{}
	for _, user := range userIDs {
		// GetUserData(user.Id, idp.AppMetadata{WTAccountId: user.Id})
		respBody = append(respBody, toUserResponse(user))
	}

	for _, value := range respBody {
		log.Info(value)
	}

	writeJSONObject(w, respBody)
}

func toUserResponse(user *server.User) *UserResponse {
	return &UserResponse{
		Id:   user.Id,
		Role: string(user.Role),
	}
}

// management/server/idp/idp.go needs to be extended, since we only save the userIDs and not extra information
