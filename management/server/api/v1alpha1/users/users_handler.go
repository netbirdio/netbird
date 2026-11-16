package users

import (
	"net/http"
	"net/url"
	"strconv"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/apiv1alpha1"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"

	nbcontext "github.com/netbirdio/netbird/management/server/context"
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

	data, userCount, err := h.accountManager.GetUsersFromAccountPaginated(r.Context(), accountID, userID, pagination, filters, store.UserSorting{})
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
	toret := store.UserFilters{}

	serviceUser, err := parseBool(v.Get("service_user"))
	if err != nil {
		return toret, err
	}

	toret.Name = v.Get("name")
	toret.ServiceUser = serviceUser

	return toret, nil
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
