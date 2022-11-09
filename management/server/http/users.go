package http

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/status"
	log "github.com/sirupsen/logrus"
	"net/http"

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

	claims := h.jwtExtractor.ExtractClaimsFromRequestContext(r, h.authAudience)
	account, _, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		log.Error(err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	vars := mux.Vars(r)
	userID := vars["id"]
	if len(userID) == 0 {
		http.Error(w, "invalid user ID", http.StatusBadRequest)
		return
	}

	req := &api.PutApiUsersIdJSONRequestBody{}
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	userRole := server.StrRoleToUserRole(req.Role)
	if userRole == server.UserRoleUnknown {
		http.Error(w, "invalid user role", http.StatusBadRequest)
		return
	}

	newUser, err := h.accountManager.SaveUser(account.Id, &server.User{
		Id:         userID,
		Role:       userRole,
		AutoGroups: req.AutoGroups,
	})
	if err != nil {
		if e, ok := status.FromError(err); ok {
			switch e.Type() {
			case status.NotFound:
				http.Error(w, fmt.Sprintf("couldn't find a user for ID %s", userID), http.StatusNotFound)
			default:
				http.Error(w, "failed to update user", http.StatusInternalServerError)
			}
		}
		return
	}
	util.WriteJSONObject(w, toUserResponse(newUser))

}

// CreateUserHandler creates a User in the system with a status "invited" (effectively this is a user invite).
func (h *UserHandler) CreateUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "", http.StatusNotFound)
	}

	claims := h.jwtExtractor.ExtractClaimsFromRequestContext(r, h.authAudience)
	account, _, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		log.Error(err)
	}

	req := &api.PostApiUsersJSONRequestBody{}
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if server.StrRoleToUserRole(req.Role) == server.UserRoleUnknown {
		http.Error(w, "unknown user role "+req.Role, http.StatusBadRequest)
		return
	}

	newUser, err := h.accountManager.CreateUser(account.Id, &server.UserInfo{
		Email:      req.Email,
		Name:       *req.Name,
		Role:       req.Role,
		AutoGroups: req.AutoGroups,
	})
	if err != nil {
		if e, ok := status.FromError(err); ok {
			switch e.Type() {
			case status.UserAlreadyExists:
				http.Error(w, "You can't invite users with an existing NetBird account.", http.StatusPreconditionFailed)
				return
			default:
			}
		}
		http.Error(w, "failed to invite", http.StatusInternalServerError)
		return
	}
	util.WriteJSONObject(w, toUserResponse(newUser))
}

// GetUsers returns a list of users of the account this user belongs to.
// It also gathers additional user data (like email and name) from the IDP manager.
func (h *UserHandler) GetUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "", http.StatusBadRequest)
	}

	claims := h.jwtExtractor.ExtractClaimsFromRequestContext(r, h.authAudience)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	data, err := h.accountManager.GetUsersFromAccount(account.Id, user.Id)
	if err != nil {
		log.Error(err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	users := make([]*api.User, 0)
	for _, r := range data {
		users = append(users, toUserResponse(r))
	}

	util.WriteJSONObject(w, users)
}

func toUserResponse(user *server.UserInfo) *api.User {

	autoGroups := user.AutoGroups
	if autoGroups == nil {
		autoGroups = []string{}
	}

	var userStatus api.UserStatus
	switch user.Status {
	case "active":
		userStatus = api.UserStatusActive
	case "invited":
		userStatus = api.UserStatusInvited
	default:
		userStatus = api.UserStatusDisabled
	}

	return &api.User{
		Id:         user.ID,
		Name:       user.Name,
		Email:      user.Email,
		Role:       user.Role,
		AutoGroups: autoGroups,
		Status:     userStatus,
	}
}
