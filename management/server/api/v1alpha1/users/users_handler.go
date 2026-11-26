package users

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/account"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/apiv1alpha1"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

type Handler struct {
	accountManager account.Manager
}

func NewHandler(accountManager account.Manager) *Handler {
	return &Handler{
		accountManager: accountManager,
	}
}

func (h *Handler) WithEndpointsForRouter(router *mux.Router) *mux.Router {
	router.HandleFunc("/users", h.getAllUsers).Methods("GET", "OPTIONS")
	router.HandleFunc("/users/{userId}", h.getUser).Methods("GET", "OPTIONS")
	return router
}

// getAllUsers returns a list of users of the account this user belongs to.
// It also gathers additional user data (like email and name) from the IDP manager.
func (h *Handler) getAllUsers(w http.ResponseWriter, r *http.Request) {
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
	pagination, err := paginationFromQuery(r.URL.Query())
	if err != nil {
		log.WithContext(r.Context()).Errorf("error parsing query: %v", err)
		util.WriteError(r.Context(), &status.Error{ErrorType: status.InvalidArgument, Message: err.Error()}, w)
		return
	}

	filters, err := filtersFromQuery(r.URL.Query())
	if err != nil {
		log.WithContext(r.Context()).Errorf("error parsing query: %v", err)
		util.WriteError(r.Context(), &status.Error{ErrorType: status.InvalidArgument, Message: err.Error()}, w)
		return
	}

	sorting, err := sortingFromQuery(r.URL.Query())
	if err != nil {
		log.WithContext(r.Context()).Errorf("error parsing query: %v", err)
		util.WriteError(r.Context(), &status.Error{ErrorType: status.InvalidArgument, Message: err.Error()}, w)
		return
	}

	data, userCount, err := h.accountManager.GetUsersFromAccountPaginated(r.Context(), accountID, userID, pagination, filters, sorting)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	users := make([]apiv1alpha1.User, 0, len(data))
	for _, d := range data {
		users = append(users, *toUserResponse(d, userID))
	}

	util.WriteJSONObject(r.Context(), w, apiv1alpha1.UserBatch{UserCount: userCount, Users: users, Page: pagination.Page, PageSize: pagination.PageSize})
}

func (h *Handler) getUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		util.WriteErrorResponse("wrong HTTP method", http.StatusMethodNotAllowed, w)
		return
	}

	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	targetUserID := mux.Vars(r)["userId"]
	if len(targetUserID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid user ID"), w)
		return
	}

	found, _, err := h.accountManager.GetUsersFromAccountPaginated(r.Context(), userAuth.AccountId, userAuth.UserId,
		store.PaginationState{Page: 1, PageSize: 1}, store.UserFilters{UserIDs: []string{targetUserID}}, store.UserSorting{})
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	if len(found) == 0 {
		util.WriteError(r.Context(), status.NewUserNotFoundError(targetUserID), w)
		return
	}

	util.WriteJSONObject(r.Context(), w, toUserResponse(found[0], userAuth.UserId))
}

func toUserResponse(user *types.UserInfo, currenUserID string) *apiv1alpha1.User {
	autoGroups := user.AutoGroups
	if autoGroups == nil {
		autoGroups = []string{}
	}

	var userStatus apiv1alpha1.UserStatus
	switch user.Status {
	case "active":
		userStatus = apiv1alpha1.UserStatusActive
	case "invited":
		userStatus = apiv1alpha1.UserStatusInvited
	default:
		userStatus = apiv1alpha1.UserStatusBlocked
	}

	if user.IsBlocked {
		userStatus = apiv1alpha1.UserStatusBlocked
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

	return &apiv1alpha1.User{
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

func paginationFromQuery(v url.Values) (store.PaginationState, error) {
	page, err := strconv.Atoi(v.Get("page"))
	if err != nil {
		return store.PaginationState{}, err
	}

	pageSize, err := strconv.Atoi(v.Get("page_size"))
	if err != nil {
		return store.PaginationState{}, err
	}

	return store.PaginationState{
		Page:     page,
		PageSize: pageSize,
	}, nil
}

func filtersFromQuery(v url.Values) (store.UserFilters, error) {
	serviceUser, err := parseBool(v.Get("service_user"))
	if err != nil {
		return store.UserFilters{}, fmt.Errorf("parse service_user: %w", err)
	}

	pendingApproval, err := parseBool(v.Get("pending_approval"))
	if err != nil {
		return store.UserFilters{}, fmt.Errorf("parse pending_approval: %w", err)
	}

	var roles []types.UserRole
	for _, value := range v["role"] {
		role := types.StrRoleToUserRole(value)
		if role == types.UserRoleUnknown {
			return store.UserFilters{}, fmt.Errorf("unknown role %q", value)
		}
		roles = append(roles, role)
	}

	return store.UserFilters{
		Name:            strings.TrimSpace(v.Get("name")),
		Email:           strings.TrimSpace(v.Get("email")),
		ServiceUser:     serviceUser,
		PendingApproval: pendingApproval,
		Roles:           roles,
		GroupIDs:        v["group_ids"],
		UserIDs:         v["user_ids"],
	}, nil
}

// sortingFromQuery parses repeated sort_by values such as "last_login,desc". The order
// defaults to ascending.
func sortingFromQuery(v url.Values) (store.UserSorting, error) {
	var sorting store.UserSorting
	for _, value := range v["sort_by"] {
		field, order, _ := strings.Cut(value, ",")

		key := store.UserSortingKey{Order: store.AscOrderBy}
		switch strings.TrimSpace(field) {
		case "is_current":
			key.Field = store.UserSortByIsCurrent
		case "role":
			key.Field = store.UserSortByRole
		case "last_login":
			key.Field = store.UserSortByLastLogin
		default:
			return store.UserSorting{}, fmt.Errorf("unknown sort field %q", field)
		}

		switch strings.TrimSpace(order) {
		case "", "asc":
		case "desc":
			key.Order = store.DescOrderBy
		default:
			return store.UserSorting{}, fmt.Errorf("unknown sort order %q", order)
		}

		sorting.Fields = append(sorting.Fields, key)
	}
	return sorting, nil
}

func parseBool(maybeBool string) (*bool, error) {
	if maybeBool == "" {
		return nil, nil //nolint:nilnil
	}

	parsed, err := strconv.ParseBool(maybeBool)
	if err != nil {
		return nil, err
	}

	return new(parsed), nil
}
