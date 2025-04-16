package users

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/permissions/roles"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/management/server/users"

	nbcontext "github.com/netbirdio/netbird/management/server/context"
)

// handler is a handler that returns users of the account
type handler struct {
	accountManager account.Manager
	usersManager   users.Manager
}

func AddEndpoints(accountManager account.Manager, usersManager users.Manager, router *mux.Router) {
	userHandler := newHandler(accountManager)
	router.HandleFunc("/users", userHandler.getAllUsers).Methods("GET", "OPTIONS")
	router.HandleFunc("/users/current", userHandler.getCurrentUser).Methods("GET", "OPTIONS")
	router.HandleFunc("/users/{userId}", userHandler.updateUser).Methods("PUT", "OPTIONS")
	router.HandleFunc("/users/{userId}", userHandler.deleteUser).Methods("DELETE", "OPTIONS")
	router.HandleFunc("/users", userHandler.createUser).Methods("POST", "OPTIONS")
	router.HandleFunc("/users/{userId}/invite", userHandler.inviteUser).Methods("POST", "OPTIONS")
	router.HandleFunc("/users/roles", userHandler.getRoles).Methods("GET", "OPTIONS")
	addUsersTokensEndpoint(accountManager, router)
}

// newHandler creates a new UsersHandler HTTP handler
func newHandler(accountManager account.Manager) *handler {
	return &handler{
		accountManager: accountManager,
	}
}

// updateUser is a PUT requests to update User data
func (h *handler) updateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		util.WriteErrorResponse("wrong HTTP method", http.StatusMethodNotAllowed, w)
		return
	}

	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId
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

	newUser, err := h.accountManager.SaveUser(r.Context(), accountID, userID, &types.User{
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
	util.WriteJSONObject(r.Context(), w, toUserResponse(newUser, userID))
}

// deleteUser is a DELETE request to delete a user
func (h *handler) deleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		util.WriteErrorResponse("wrong HTTP method", http.StatusMethodNotAllowed, w)
		return
	}

	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId
	vars := mux.Vars(r)
	targetUserID := vars["userId"]
	if len(targetUserID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid user ID"), w)
		return
	}

	err = h.accountManager.DeleteUser(r.Context(), accountID, userID, targetUserID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, util.EmptyObject{})
}

// createUser creates a User in the system with a status "invited" (effectively this is a user invite).
func (h *handler) createUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		util.WriteErrorResponse("wrong HTTP method", http.StatusMethodNotAllowed, w)
		return
	}

	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	accountID, userID := userAuth.AccountId, userAuth.UserId

	req := &api.PostApiUsersJSONRequestBody{}
	err = json.NewDecoder(r.Body).Decode(&req)
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

	newUser, err := h.accountManager.CreateUser(r.Context(), accountID, userID, &types.UserInfo{
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
	util.WriteJSONObject(r.Context(), w, toUserResponse(newUser, userID))
}

// getAllUsers returns a list of users of the account this user belongs to.
// It also gathers additional user data (like email and name) from the IDP manager.
func (h *handler) getAllUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		util.WriteErrorResponse("wrong HTTP method", http.StatusMethodNotAllowed, w)
		return
	}

	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId
	data, err := h.accountManager.GetUsersFromAccount(r.Context(), accountID, userID)
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
			users = append(users, toUserResponse(d, userID))
			continue
		}

		includeServiceUser, err := strconv.ParseBool(serviceUser)
		log.WithContext(r.Context()).Debugf("Should include service user: %v", includeServiceUser)
		if err != nil {
			util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid service_user query parameter"), w)
			return
		}
		if includeServiceUser == d.IsServiceUser {
			users = append(users, toUserResponse(d, userID))
		}
	}

	util.WriteJSONObject(r.Context(), w, users)
}

// inviteUser resend invitations to users who haven't activated their accounts,
// prior to the expiration period.
func (h *handler) inviteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		util.WriteErrorResponse("wrong HTTP method", http.StatusMethodNotAllowed, w)
		return
	}

	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	accountID, userID := userAuth.AccountId, userAuth.UserId

	vars := mux.Vars(r)
	targetUserID := vars["userId"]
	if len(targetUserID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid user ID"), w)
		return
	}

	err = h.accountManager.InviteUser(r.Context(), accountID, userID, targetUserID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, util.EmptyObject{})
}

func (h *handler) getCurrentUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		util.WriteErrorResponse("wrong HTTP method", http.StatusMethodNotAllowed, w)
		return
	}
	ctx := r.Context()
	userAuth, err := nbcontext.GetUserAuthFromContext(ctx)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId

	user, err := h.accountManager.GetCurrentUserInfo(ctx, accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, toUserWithPermissionsResponse(user, userID))
}

func (h *handler) getRoles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		util.WriteErrorResponse("wrong HTTP method", http.StatusMethodNotAllowed, w)
		return
	}
	ctx := r.Context()
	userAuth, err := nbcontext.GetUserAuthFromContext(ctx)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId

	roles, err := h.usersManager.GetRoles(ctx, accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, toRolesResponse(roles))
}

func toRolesResponse(roles map[types.UserRole]roles.RolePermissions) []api.RolePermissions {
	result := make([]api.RolePermissions, 0, len(roles))
	for _, permissions := range roles {
		rolePermissions := api.RolePermissions{
			Role: string(permissions.Role),
		}

		if len(permissions.AutoAllowNew) > 0 {
			rolePermissions.Default = make(map[string]bool)
			for k, v := range permissions.AutoAllowNew {
				rolePermissions.Default[string(k)] = v
			}
		}

		if len(permissions.Permissions) > 0 {
			modules := make(map[string]map[string]bool)
			for module, operations := range permissions.Permissions {
				if len(operations) == 0 {
					continue
				}

				access := make(map[string]bool)
				for k, v := range operations {
					access[string(k)] = v
				}
				modules[string(module)] = access
			}
			rolePermissions.Modules = &modules
		}

		result = append(result, rolePermissions)
	}
	return result
}

func toUserWithPermissionsResponse(user *users.UserInfoWithPermissions, userID string) *api.User {
	response := toUserResponse(user.UserInfo, userID)

	permissions := api.UserPermissions{
		IsRestricted: user.Restricted,
	}

	if len(user.Permissions.AutoAllowNew) > 0 {
		permissions.Default = make(map[string]bool)
		for k, v := range user.Permissions.AutoAllowNew {
			permissions.Default[string(k)] = v
		}
	}

	if len(user.Permissions.Permissions) > 0 {
		modules := make(map[string]map[string]bool)
		for module, operations := range user.Permissions.Permissions {
			if len(operations) == 0 {
				continue
			}

			access := make(map[string]bool)
			for k, v := range operations {
				access[string(k)] = v
			}
			modules[string(module)] = access
		}
		permissions.Modules = &modules
	}

	response.Permissions = permissions

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
	}
}
