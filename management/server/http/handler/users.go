package handler

import (
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
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
	Role  string `json:"role"`
}

func NewUserHandler(accountManager server.AccountManager, authAudience string) *UserHandler {
	return &UserHandler{
		accountManager: accountManager,
		authAudience:   authAudience,
		jwtExtractor:   *jwtclaims.NewClaimsExtractor(nil),
	}
}

// GetUsers returns a list of users of the account this user belongs to.
// It also gathers additional user data (like email and name) from the IDP manager.
func (h *UserHandler) GetUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "", http.StatusBadRequest)
	}

	account, err := getJWTAccount(h.accountManager, h.jwtExtractor, h.authAudience, r)
	if err != nil {
		log.Error(err)
	}

	data, err := h.accountManager.GetUsersFromAccount(account.Id)
	if err != nil {
		log.Error(err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	users := []*UserResponse{}
	for _, r := range data {
		users = append(users, toUserResponse(r))
	}

	writeJSONObject(w, users)
}

func toUserResponse(user *server.UserInfo) *UserResponse {
	return &UserResponse{
		ID:    user.ID,
		Name:  user.Name,
		Email: user.Email,
		Role:  user.Role,
	}
}
