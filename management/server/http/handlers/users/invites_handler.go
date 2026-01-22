package users

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/server/account"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

// invitesHandler handles user invite operations
type invitesHandler struct {
	accountManager account.Manager
}

// AddInvitesEndpoints registers invite-related endpoints
func AddInvitesEndpoints(accountManager account.Manager, router *mux.Router) {
	h := &invitesHandler{accountManager: accountManager}

	// Authenticated endpoints (require admin)
	router.HandleFunc("/users/invites", h.createInvite).Methods("POST", "OPTIONS")
	router.HandleFunc("/users/invites/{email}", h.regenerateInvite).Methods("POST", "OPTIONS")
}

// AddPublicInvitesEndpoints registers public (unauthenticated) invite endpoints
func AddPublicInvitesEndpoints(accountManager account.Manager, router *mux.Router) {
	h := &invitesHandler{accountManager: accountManager}

	// Public endpoints (no auth required, protected by token)
	router.HandleFunc("/users/invites/{token}", h.getInviteInfo).Methods("GET", "OPTIONS")
	router.HandleFunc("/users/invites/{token}/accept", h.acceptInvite).Methods("POST", "OPTIONS")
}

// createInviteRequest represents the request body for creating an invite
type createInviteRequest struct {
	Email      string   `json:"email"`
	Name       string   `json:"name"`
	Role       string   `json:"role"`
	AutoGroups []string `json:"auto_groups"`
	ExpiresIn  int      `json:"expires_in,omitempty"` // seconds, optional
}

// createInviteResponse represents the response for creating an invite
type createInviteResponse struct {
	ID              string   `json:"id"`
	Email           string   `json:"email"`
	Name            string   `json:"name"`
	Role            string   `json:"role"`
	AutoGroups      []string `json:"auto_groups"`
	Status          string   `json:"status"`
	InviteLink      string   `json:"invite_link"`
	InviteExpiresAt string   `json:"invite_expires_at"`
}

// inviteInfoResponse represents the response for getting invite info
type inviteInfoResponse struct {
	Email     string `json:"email"`
	Name      string `json:"name"`
	ExpiresAt string `json:"expires_at"`
	Valid     bool   `json:"valid"`
}

// acceptInviteRequest represents the request body for accepting an invite
type acceptInviteRequest struct {
	Password string `json:"password"`
}

// regenerateInviteRequest represents the request body for regenerating an invite
type regenerateInviteRequest struct {
	ExpiresIn int `json:"expires_in,omitempty"` // seconds, optional
}

// regenerateInviteResponse represents the response for regenerating an invite
type regenerateInviteResponse struct {
	InviteLink      string `json:"invite_link"`
	InviteExpiresAt string `json:"invite_expires_at"`
}

// createInvite handles POST /api/users/invites
func (h *invitesHandler) createInvite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		util.WriteErrorResponse("wrong HTTP method", http.StatusMethodNotAllowed, w)
		return
	}

	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	var req createInviteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	if req.Email == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "email is required"), w)
		return
	}

	if req.Name == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "name is required"), w)
		return
	}

	if types.StrRoleToUserRole(req.Role) == types.UserRoleUnknown {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid role"), w)
		return
	}

	invite := &types.UserInfo{
		Email:      req.Email,
		Name:       req.Name,
		Role:       req.Role,
		AutoGroups: req.AutoGroups,
	}

	result, err := h.accountManager.CreateUserInvite(r.Context(), userAuth.AccountId, userAuth.UserId, invite, req.ExpiresIn)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	autoGroups := result.UserInfo.AutoGroups
	if autoGroups == nil {
		autoGroups = []string{}
	}

	util.WriteJSONObject(r.Context(), w, &createInviteResponse{
		ID:              result.UserInfo.ID,
		Email:           result.UserInfo.Email,
		Name:            result.UserInfo.Name,
		Role:            result.UserInfo.Role,
		AutoGroups:      autoGroups,
		Status:          result.UserInfo.Status,
		InviteLink:      result.InviteLink,
		InviteExpiresAt: result.InviteExpiresAt.UTC().Format("2006-01-02T15:04:05Z"),
	})
}

// getInviteInfo handles GET /api/users/invites/{token}
func (h *invitesHandler) getInviteInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		util.WriteErrorResponse("wrong HTTP method", http.StatusMethodNotAllowed, w)
		return
	}

	vars := mux.Vars(r)
	token := vars["token"]
	if token == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "token is required"), w)
		return
	}

	info, err := h.accountManager.GetUserInviteInfo(r.Context(), token)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, &inviteInfoResponse{
		Email:     info.Email,
		Name:      info.Name,
		ExpiresAt: info.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"),
		Valid:     info.Valid,
	})
}

// acceptInvite handles POST /api/users/invites/{token}/accept
func (h *invitesHandler) acceptInvite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		util.WriteErrorResponse("wrong HTTP method", http.StatusMethodNotAllowed, w)
		return
	}

	vars := mux.Vars(r)
	token := vars["token"]
	if token == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "token is required"), w)
		return
	}

	var req acceptInviteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	if req.Password == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "password is required"), w)
		return
	}

	err := h.accountManager.AcceptUserInvite(r.Context(), token, req.Password)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, struct {
		Success bool `json:"success"`
	}{Success: true})
}

// regenerateInvite handles POST /api/users/invites/{email}
func (h *invitesHandler) regenerateInvite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		util.WriteErrorResponse("wrong HTTP method", http.StatusMethodNotAllowed, w)
		return
	}

	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	vars := mux.Vars(r)
	email := vars["email"]
	if email == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "email is required"), w)
		return
	}

	var req regenerateInviteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Allow empty body - expiresIn is optional
		req = regenerateInviteRequest{}
	}

	result, err := h.accountManager.RegenerateUserInvite(r.Context(), userAuth.AccountId, userAuth.UserId, email, req.ExpiresIn)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, &regenerateInviteResponse{
		InviteLink:      result.InviteLink,
		InviteExpiresAt: result.InviteExpiresAt.UTC().Format("2006-01-02T15:04:05Z"),
	})
}
