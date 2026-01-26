package users

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/server/account"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/http/middleware"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

// publicInviteRateLimiter limits public invite requests by IP address to prevent brute-force attacks
var publicInviteRateLimiter = middleware.NewAPIRateLimiter(&middleware.RateLimiterConfig{
	RequestsPerMinute: 10, // 10 attempts per minute per IP
	Burst:             5,  // Allow burst of 5 requests
	CleanupInterval:   10 * time.Minute,
	LimiterTTL:        30 * time.Minute,
})

// toUserInviteResponse converts a UserInvite to an API response.
func toUserInviteResponse(invite *types.UserInvite) api.UserInvite {
	autoGroups := invite.UserInfo.AutoGroups
	if autoGroups == nil {
		autoGroups = []string{}
	}
	var inviteLink *string
	if invite.InviteToken != "" {
		inviteLink = &invite.InviteToken
	}
	return api.UserInvite{
		Id:          invite.UserInfo.ID,
		Email:       invite.UserInfo.Email,
		Name:        invite.UserInfo.Name,
		Role:        invite.UserInfo.Role,
		AutoGroups:  autoGroups,
		ExpiresAt:   invite.InviteExpiresAt.UTC(),
		CreatedAt:   invite.InviteCreatedAt.UTC(),
		Expired:     time.Now().After(invite.InviteExpiresAt),
		InviteToken: inviteLink,
	}
}

// invitesHandler handles user invite operations
type invitesHandler struct {
	accountManager account.Manager
}

// AddInvitesEndpoints registers invite-related endpoints
func AddInvitesEndpoints(accountManager account.Manager, router *mux.Router) {
	h := &invitesHandler{accountManager: accountManager}

	// Authenticated endpoints (require admin)
	router.HandleFunc("/users/invites", h.listInvites).Methods("GET", "OPTIONS")
	router.HandleFunc("/users/invites", h.createInvite).Methods("POST", "OPTIONS")
	router.HandleFunc("/users/invites/{inviteId}", h.deleteInvite).Methods("DELETE", "OPTIONS")
	router.HandleFunc("/users/invites/{inviteId}/regenerate", h.regenerateInvite).Methods("POST", "OPTIONS")
}

// AddPublicInvitesEndpoints registers public (unauthenticated) invite endpoints with rate limiting
func AddPublicInvitesEndpoints(accountManager account.Manager, router *mux.Router) {
	h := &invitesHandler{accountManager: accountManager}

	// Create a subrouter for public invite endpoints with rate limiting middleware
	publicRouter := router.PathPrefix("/users/invites").Subrouter()
	publicRouter.Use(publicInviteRateLimiter.Middleware)

	// Public endpoints (no auth required, protected by token and rate limited)
	publicRouter.HandleFunc("/{token}", h.getInviteInfo).Methods("GET", "OPTIONS")
	publicRouter.HandleFunc("/{token}/accept", h.acceptInvite).Methods("POST", "OPTIONS")
}

// listInvites handles GET /api/users/invites
func (h *invitesHandler) listInvites(w http.ResponseWriter, r *http.Request) {

	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	invites, err := h.accountManager.ListUserInvites(r.Context(), userAuth.AccountId, userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	resp := make([]api.UserInvite, 0, len(invites))
	for _, invite := range invites {
		resp = append(resp, toUserInviteResponse(invite))
	}

	util.WriteJSONObject(r.Context(), w, resp)
}

// createInvite handles POST /api/users/invites
func (h *invitesHandler) createInvite(w http.ResponseWriter, r *http.Request) {

	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	var req api.UserInviteCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	invite := &types.UserInfo{
		Email:      req.Email,
		Name:       req.Name,
		Role:       req.Role,
		AutoGroups: req.AutoGroups,
	}

	expiresIn := 0
	if req.ExpiresIn != nil {
		expiresIn = *req.ExpiresIn
	}

	result, err := h.accountManager.CreateUserInvite(r.Context(), userAuth.AccountId, userAuth.UserId, invite, expiresIn)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	result.InviteCreatedAt = time.Now().UTC()
	resp := toUserInviteResponse(result)
	util.WriteJSONObject(r.Context(), w, &resp)
}

// getInviteInfo handles GET /api/users/invites/{token}
func (h *invitesHandler) getInviteInfo(w http.ResponseWriter, r *http.Request) {

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

	expiresAt := info.ExpiresAt.UTC()
	util.WriteJSONObject(r.Context(), w, &api.UserInviteInfo{
		Email:     info.Email,
		Name:      info.Name,
		ExpiresAt: expiresAt,
		Valid:     info.Valid,
		InvitedBy: info.InvitedBy,
	})
}

// acceptInvite handles POST /api/users/invites/{token}/accept
func (h *invitesHandler) acceptInvite(w http.ResponseWriter, r *http.Request) {

	vars := mux.Vars(r)
	token := vars["token"]
	if token == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "token is required"), w)
		return
	}

	var req api.UserInviteAcceptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	err := h.accountManager.AcceptUserInvite(r.Context(), token, req.Password)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, &api.UserInviteAcceptResponse{Success: true})
}

// regenerateInvite handles POST /api/users/invites/{inviteId}/regenerate
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
	inviteID := vars["inviteId"]
	if inviteID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invite ID is required"), w)
		return
	}

	var req api.UserInviteRegenerateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Allow empty body (io.EOF) - expiresIn is optional
		if !errors.Is(err, io.EOF) {
			util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
			return
		}
	}

	expiresIn := 0
	if req.ExpiresIn != nil {
		expiresIn = *req.ExpiresIn
	}

	result, err := h.accountManager.RegenerateUserInvite(r.Context(), userAuth.AccountId, userAuth.UserId, inviteID, expiresIn)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	expiresAt := result.InviteExpiresAt.UTC()
	util.WriteJSONObject(r.Context(), w, &api.UserInviteRegenerateResponse{
		InviteToken:     result.InviteToken,
		InviteExpiresAt: expiresAt,
	})
}

// deleteInvite handles DELETE /api/users/invites/{inviteId}
func (h *invitesHandler) deleteInvite(w http.ResponseWriter, r *http.Request) {

	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	vars := mux.Vars(r)
	inviteID := vars["inviteId"]
	if inviteID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invite ID is required"), w)
		return
	}

	err = h.accountManager.DeleteUserInvite(r.Context(), userAuth.AccountId, userAuth.UserId, inviteID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, util.EmptyObject{})
}
