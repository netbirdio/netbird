package http

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/netbirdio/netbird/management/server/http/api"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

func NewUserHandler(accountManager server.AccountManager, authAudience string) *UserHandler {
	return &UserHandler{
		accountManager: accountManager,
		authAudience:   authAudience,
		jwtExtractor:   *jwtclaims.NewClaimsExtractor(nil),
	}
}

// UpdateUser is a PUT requests to update User data
func (h *UserHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "", http.StatusBadRequest)
	}

	account, err := getJWTAccount(h.accountManager, h.jwtExtractor, h.authAudience, r)
	if err != nil {
		log.Error(err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	vars := mux.Vars(r)
	userID := vars["id"]
	if len(userID) == 0 {
		http.Error(w, "invalid key Id", http.StatusBadRequest)
		return
	}

	req := &api.PutApiUsersIdJSONRequestBody{}
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	newUser, err := h.accountManager.SaveUser(account.Id, &server.User{
		Id:         userID,
		AutoGroups: req.AutoGroups,
	})
	if err != nil {
		if e, ok := status.FromError(err); ok {
			switch e.Code() {
			case codes.NotFound:
				http.Error(w, fmt.Sprintf("couldn't find a user for ID %s", userID), http.StatusNotFound)
			default:
				http.Error(w, "failed to update user", http.StatusInternalServerError)
			}
		}
		return
	}
	writeJSONObject(w, toUserResponse(newUser))

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

	users := []*api.User{}
	for _, r := range data {
		users = append(users, toUserResponse(r))
	}

	writeJSONObject(w, users)
}

func toUserResponse(user *server.UserInfo) *api.User {
	return &api.User{
		Id:    user.ID,
		Name:  user.Name,
		Email: user.Email,
		Role:  user.Role,
	}
}
