package http

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/status"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
)

// UsersHandler is a handler that returns users of the account
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
	userID := vars["userId"]
	if len(userID) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid user ID"), w)
		return
	}

	existingUser, ok := account.Users[userID]
	if !ok {
		util.WriteError(status.Errorf(status.NotFound, "couldn't find user with ID %s", userID), w)
		return
	}

	req := &api.PutApiUsersUserIdJSONRequestBody{}
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	if req.AutoGroups == nil {
		util.WriteErrorResponse("auto_groups field can't be absent", http.StatusBadRequest, w)
		return
	}

	userRole := server.StrRoleToUserRole(req.Role)
	if userRole == server.UserRoleUnknown {
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid user role"), w)
		return
	}

	newUser, err := h.accountManager.SaveUser(account.Id, user.Id, &server.User{
		Id:                   userID,
		Role:                 userRole,
		AutoGroups:           req.AutoGroups,
		Blocked:              req.IsBlocked,
		Issued:               existingUser.Issued,
		IntegrationReference: existingUser.IntegrationReference,
	})

	if err != nil {
		util.WriteError(err, w)
		return
	}
	util.WriteJSONObject(w, toUserResponse(newUser, claims.UserId))
}

// DeleteUser is a DELETE request to delete a user
func (h *UsersHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
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
	targetUserID := vars["userId"]
	if len(targetUserID) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid user ID"), w)
		return
	}

	err = h.accountManager.DeleteUser(account.Id, user.Id, targetUserID)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	util.WriteJSONObject(w, emptyObject{})
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

	email := ""
	if req.Email != nil {
		email = *req.Email
	}

	name := ""
	if req.Name != nil {
		name = *req.Name
	}

	newUser, err := h.accountManager.CreateUser(account.Id, user.Id, &server.UserInfo{
		Email:         email,
		Name:          name,
		Role:          req.Role,
		AutoGroups:    req.AutoGroups,
		IsServiceUser: req.IsServiceUser,
		Issued:        server.UserIssuedAPI,
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

	serviceUser := r.URL.Query().Get("service_user")

	users := make([]*api.User, 0)
	for _, r := range data {
		if r.NonDeletable {
			continue
		}
		if serviceUser == "" {
			users = append(users, toUserResponse(r, claims.UserId))
			continue
		}

		includeServiceUser, err := strconv.ParseBool(serviceUser)
		log.Debugf("Should include service user: %v", includeServiceUser)
		if err != nil {
			util.WriteError(status.Errorf(status.InvalidArgument, "invalid service_user query parameter"), w)
			return
		}
		if includeServiceUser == r.IsServiceUser {
			users = append(users, toUserResponse(r, claims.UserId))
		}
	}

	util.WriteJSONObject(w, users)
}

// InviteUser resend invitations to users who haven't activated their accounts,
// prior to the expiration period.
func (h *UsersHandler) InviteUser(w http.ResponseWriter, r *http.Request) {
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

	vars := mux.Vars(r)
	targetUserID := vars["userId"]
	if len(targetUserID) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid user ID"), w)
		return
	}

	err = h.accountManager.InviteUser(account.Id, user.Id, targetUserID)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	util.WriteJSONObject(w, emptyObject{})
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
		userStatus = api.UserStatusBlocked
	}

	if user.IsBlocked {
		userStatus = api.UserStatusBlocked
	}

	isCurrent := user.ID == currenUserID
	return &api.User{
		Id:            user.ID,
		Name:          user.Name,
		Email:         user.Email,
		Role:          user.Role,
		AutoGroups:    autoGroups,
		Status:        userStatus,
		IsCurrent:     &isCurrent,
		IsServiceUser: &user.IsServiceUser,
		IsBlocked:     user.IsBlocked,
		LastLogin:     &user.LastLogin,
		Issued:        &user.Issued,
		Permissions: &api.UserPermissions{
			DashboardView: (*api.UserPermissionsDashboardView)(&user.Permissions.DashboardView),
		},
	}
}
