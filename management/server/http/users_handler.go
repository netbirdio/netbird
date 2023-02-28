package http

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/status"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
)

type UsersHandler struct {
	accountManager  server.AccountManager
	claimsExtractor *jwtclaims.ClaimsExtractor
}

// NewUsersHandler creates a new UsersHandler HTTP handler
func NewUsersHandler(accountManager server.AccountManager, authCfg AuthCfg) *UsersHandler {
	return &UsersHandler{
		accountManager: accountManager,
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithAudience(authCfg.Audience),
			jwtclaims.WithUserIDClaim(authCfg.UserIDClaim),
		),
	}
}

// UpdateUser is a PUT requests to update User data
func (h *UsersHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		util.WriteErrorResponse("wrong HTTP method", http.StatusMethodNotAllowed, w)
		return
	}

	claims := h.claimsExtractor.FromRequestContext(r)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	vars := mux.Vars(r)
	userID := vars["id"]
	if len(userID) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid user ID"), w)
		return
	}

	req := &api.PutApiUsersIdJSONRequestBody{}
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	userRole := server.StrRoleToUserRole(req.Role)
	if userRole == server.UserRoleUnknown {
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid user role"), w)
		return
	}

	newUser, err := h.accountManager.SaveUser(account.Id, user.Id, &server.User{
		Id:         userID,
		Role:       userRole,
		AutoGroups: req.AutoGroups,
	})
	if err != nil {
		util.WriteError(err, w)
		return
	}
	util.WriteJSONObject(w, toUserResponse(newUser, claims.UserId))
}

// CreateUser creates a User in the system with a status "invited" (effectively this is a user invite).
func (h *UsersHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		util.WriteErrorResponse("wrong HTTP method", http.StatusMethodNotAllowed, w)
		return
	}

	claims := h.claimsExtractor.FromRequestContext(r)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	req := &api.PostApiUsersJSONRequestBody{}
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	if server.StrRoleToUserRole(req.Role) == server.UserRoleUnknown {
		util.WriteError(status.Errorf(status.InvalidArgument, "unknown user role %s", req.Role), w)
		return
	}

	newUser, err := h.accountManager.CreateUser(account.Id, user.Id, &server.UserInfo{
		Email:      req.Email,
		Name:       *req.Name,
		Role:       req.Role,
		AutoGroups: req.AutoGroups,
	})
	if err != nil {
		util.WriteError(err, w)
		return
	}
	util.WriteJSONObject(w, toUserResponse(newUser, claims.UserId))
}

// GetAllUsers returns a list of users of the account this user belongs to.
// It also gathers additional user data (like email and name) from the IDP manager.
func (h *UsersHandler) GetAllUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		util.WriteErrorResponse("wrong HTTP method", http.StatusMethodNotAllowed, w)
		return
	}

	claims := h.claimsExtractor.FromRequestContext(r)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	data, err := h.accountManager.GetUsersFromAccount(account.Id, user.Id)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	users := make([]*api.User, 0)
	for _, r := range data {
		users = append(users, toUserResponse(r, claims.UserId))
	}

	util.WriteJSONObject(w, users)
}

func toUserResponse(user *server.UserInfo, currenUserID string) *api.User {
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

	isCurrent := user.ID == currenUserID
	return &api.User{
		Id:         user.ID,
		Name:       user.Name,
		Email:      user.Email,
		Role:       user.Role,
		AutoGroups: autoGroups,
		Status:     userStatus,
		IsCurrent:  &isCurrent,
	}
}
