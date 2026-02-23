package users

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/management/server/users"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

// handler is a handler that returns users of the account
type handler struct {
	accountManager account.Manager
}

func AddEndpoints(accountManager account.Manager, router *mux.Router, permissionsManager permissions.Manager) {
	userHandler := newHandler(accountManager)
	router.HandleFunc("/users", permissionsManager.WithPermission(modules.Users, operations.Read, userHandler.getAllUsers)).Methods("GET", "OPTIONS")
	router.HandleFunc("/users/current", permissionsManager.WithPermission(modules.Users, operations.Read, userHandler.getCurrentUser)).Methods("GET", "OPTIONS")
	router.HandleFunc("/users/{userId}", permissionsManager.WithPermission(modules.Users, operations.Update, userHandler.updateUser)).Methods("PUT", "OPTIONS")
	router.HandleFunc("/users/{userId}", permissionsManager.WithPermission(modules.Users, operations.Delete, userHandler.deleteUser)).Methods("DELETE", "OPTIONS")
	router.HandleFunc("/users", permissionsManager.WithPermission(modules.Users, operations.Create, userHandler.createUser)).Methods("POST", "OPTIONS")
	router.HandleFunc("/users/{userId}/invite", permissionsManager.WithPermission(modules.Users, operations.Create, userHandler.inviteUser)).Methods("POST", "OPTIONS")
	router.HandleFunc("/users/{userId}/approve", permissionsManager.WithPermission(modules.Users, operations.Update, userHandler.approveUser)).Methods("POST", "OPTIONS")
	router.HandleFunc("/users/{userId}/reject", permissionsManager.WithPermission(modules.Users, operations.Delete, userHandler.rejectUser)).Methods("DELETE", "OPTIONS")
	router.HandleFunc("/users/{userId}/password", permissionsManager.WithPermission(modules.Users, operations.Update, userHandler.changePassword)).Methods("PUT", "OPTIONS")
	addUsersTokensEndpoint(accountManager, router, permissionsManager)
}

// newHandler creates a new UsersHandler HTTP handler
func newHandler(accountManager account.Manager) *handler {
	return &handler{
		accountManager: accountManager,
	}
}

// updateUser is a PUT requests to update User data
func (h *handler) updateUser(w http.ResponseWriter, r *http.Request, userAuth *auth.UserAuth) {
	if r.Method != http.MethodPut {
		util.WriteErrorResponse("wrong HTTP method", http.StatusMethodNotAllowed, w)
		return
	}

	vars := mux.Vars(r)
	targetUserID := vars["userId"]
	if len(targetUserID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid user ID"), w)
		return
	}

	existingUser, err := h.accountManager.GetUserByID(r.Context(), targetUserID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
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

	userRole := types.StrRoleToUserRole(req.Role)
	if userRole == types.UserRoleUnknown {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid user role"), w)
		return
	}

	newUser, err := h.accountManager.SaveUser(r.Context(), userAuth.AccountId, userAuth.UserId, &types.User{
		Id:                   targetUserID,
		Role:                 userRole,
		AutoGroups:           req.AutoGroups,
		Blocked:              req.IsBlocked,
		Issued:               existingUser.Issued,
		IntegrationReference: existingUser.IntegrationReference,
	})

	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, toUserResponse(newUser, userAuth.UserId))
}

// deleteUser is a DELETE request to delete a user
func (h *handler) deleteUser(w http.ResponseWriter, r *http.Request, userAuth *auth.UserAuth) {
	if r.Method != http.MethodDelete {
		util.WriteErrorResponse("wrong HTTP method", http.StatusMethodNotAllowed, w)
		return
	}

	vars := mux.Vars(r)
	targetUserID := vars["userId"]
	if len(targetUserID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid user ID"), w)
		return
	}

	err := h.accountManager.DeleteUser(r.Context(), userAuth.AccountId, userAuth.UserId, targetUserID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, util.EmptyObject{})
}

// createUser creates a User in the system with a status "invited" (effectively this is a user invite).
func (h *handler) createUser(w http.ResponseWriter, r *http.Request, userAuth *auth.UserAuth) {
	if r.Method != http.MethodPost {
		util.WriteErrorResponse("wrong HTTP method", http.StatusMethodNotAllowed, w)
		return
	}

	req := &api.PostApiUsersJSONRequestBody{}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	if types.StrRoleToUserRole(req.Role) == types.UserRoleUnknown {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "unknown user role %s", req.Role), w)
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

	newUser, err := h.accountManager.CreateUser(r.Context(), userAuth.AccountId, userAuth.UserId, &types.UserInfo{
		Email:         email,
		Name:          name,
		Role:          req.Role,
		AutoGroups:    req.AutoGroups,
		IsServiceUser: req.IsServiceUser,
		Issued:        types.UserIssuedAPI,
	})
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, toUserResponse(newUser, userAuth.UserId))
}

// getAllUsers returns a list of users of the account this user belongs to.
// It also gathers additional user data (like email and name) from the IDP manager.
func (h *handler) getAllUsers(w http.ResponseWriter, r *http.Request, userAuth *auth.UserAuth) {
	if r.Method != http.MethodGet {
		util.WriteErrorResponse("wrong HTTP method", http.StatusMethodNotAllowed, w)
		return
	}

	data, err := h.accountManager.GetUsersFromAccount(r.Context(), userAuth.AccountId, userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	serviceUser := r.URL.Query().Get("service_user")

	users := make([]*api.User, 0)
	for _, d := range data {
		if d.NonDeletable {
			continue
		}
		if serviceUser == "" {
			users = append(users, toUserResponse(d, userAuth.UserId))
			continue
		}

		includeServiceUser, err := strconv.ParseBool(serviceUser)
		log.WithContext(r.Context()).Debugf("Should include service user: %v", includeServiceUser)
		if err != nil {
			util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid service_user query parameter"), w)
			return
		}
		if includeServiceUser == d.IsServiceUser {
			users = append(users, toUserResponse(d, userAuth.UserId))
		}
	}

	util.WriteJSONObject(r.Context(), w, users)
}

// inviteUser resend invitations to users who haven't activated their accounts,
// prior to the expiration period.
func (h *handler) inviteUser(w http.ResponseWriter, r *http.Request, userAuth *auth.UserAuth) {
	if r.Method != http.MethodPost {
		util.WriteErrorResponse("wrong HTTP method", http.StatusMethodNotAllowed, w)
		return
	}

	vars := mux.Vars(r)
	targetUserID := vars["userId"]
	if len(targetUserID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid user ID"), w)
		return
	}

	err := h.accountManager.InviteUser(r.Context(), userAuth.AccountId, userAuth.UserId, targetUserID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, util.EmptyObject{})
}

func (h *handler) getCurrentUser(w http.ResponseWriter, r *http.Request, userAuth *auth.UserAuth) {
	if r.Method != http.MethodGet {
		util.WriteErrorResponse("wrong HTTP method", http.StatusMethodNotAllowed, w)
		return
	}

	user, err := h.accountManager.GetCurrentUserInfo(r.Context(), *userAuth)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, toUserWithPermissionsResponse(user, userAuth.UserId))
}

func toUserWithPermissionsResponse(user *users.UserInfoWithPermissions, userID string) *api.User {
	response := toUserResponse(user.UserInfo, userID)

	// stringify modules and operations keys
	modules := make(map[string]map[string]bool)
	for module, operations := range user.Permissions {
		modules[string(module)] = make(map[string]bool)
		for op, val := range operations {
			modules[string(module)][string(op)] = val
		}
	}

	response.Permissions = &api.UserPermissions{
		IsRestricted: user.Restricted,
		Modules:      modules,
	}

	return response
}

func toUserResponse(user *types.UserInfo, currenUserID string) *api.User {
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

	var password *string
	if user.Password != "" {
		password = &user.Password
	}

	var idpID *string
	if user.IdPID != "" {
		idpID = &user.IdPID
	}

	return &api.User{
		Id:              user.ID,
		Name:            user.Name,
		Email:           user.Email,
		Role:            user.Role,
		AutoGroups:      autoGroups,
		Status:          userStatus,
		IsCurrent:       &isCurrent,
		IsServiceUser:   &user.IsServiceUser,
		IsBlocked:       user.IsBlocked,
		LastLogin:       &user.LastLogin,
		Issued:          &user.Issued,
		PendingApproval: user.PendingApproval,
		Password:        password,
		IdpId:           idpID,
	}
}

// approveUser is a POST request to approve a user that is pending approval
func (h *handler) approveUser(w http.ResponseWriter, r *http.Request, userAuth *auth.UserAuth) {
	if r.Method != http.MethodPost {
		util.WriteErrorResponse("wrong HTTP method", http.StatusMethodNotAllowed, w)
		return
	}

	vars := mux.Vars(r)
	targetUserID := vars["userId"]
	if len(targetUserID) == 0 {
		util.WriteErrorResponse("invalid user ID", http.StatusBadRequest, w)
		return
	}

	user, err := h.accountManager.ApproveUser(r.Context(), userAuth.AccountId, userAuth.UserId, targetUserID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	userResponse := toUserResponse(user, userAuth.UserId)
	util.WriteJSONObject(r.Context(), w, userResponse)
}

// rejectUser is a DELETE request to reject a user that is pending approval
func (h *handler) rejectUser(w http.ResponseWriter, r *http.Request, userAuth *auth.UserAuth) {
	if r.Method != http.MethodDelete {
		util.WriteErrorResponse("wrong HTTP method", http.StatusMethodNotAllowed, w)
		return
	}

	vars := mux.Vars(r)
	targetUserID := vars["userId"]
	if len(targetUserID) == 0 {
		util.WriteErrorResponse("invalid user ID", http.StatusBadRequest, w)
		return
	}

	err := h.accountManager.RejectUser(r.Context(), userAuth.AccountId, userAuth.UserId, targetUserID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, util.EmptyObject{})
}

// passwordChangeRequest represents the request body for password change
type passwordChangeRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

// changePassword is a PUT request to change user's password.
// Only available when embedded IDP is enabled.
// Users can only change their own password.
func (h *handler) changePassword(w http.ResponseWriter, r *http.Request, userAuth *auth.UserAuth) {
	if r.Method != http.MethodPut {
		util.WriteErrorResponse("wrong HTTP method", http.StatusMethodNotAllowed, w)
		return
	}

	vars := mux.Vars(r)
	targetUserID := vars["userId"]
	if len(targetUserID) == 0 {
		util.WriteErrorResponse("invalid user ID", http.StatusBadRequest, w)
		return
	}

	var req passwordChangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	err := h.accountManager.UpdateUserPassword(r.Context(), userAuth.AccountId, userAuth.UserId, targetUserID, req.OldPassword, req.NewPassword)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, util.EmptyObject{})
}
