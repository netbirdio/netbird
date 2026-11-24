package groups

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/account"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	grouphandlers "github.com/netbirdio/netbird/management/server/http/handlers/groups"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/apiv1alpha1"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

// Handler serves the group endpoints of the v1alpha1 API.
type Handler struct {
	accountManager     account.Manager
	permissionsManager permissions.Manager
}

// NewHandler creates a groups handler.
func NewHandler(accountManager account.Manager, permissionsManager permissions.Manager) *Handler {
	return &Handler{
		accountManager:     accountManager,
		permissionsManager: permissionsManager,
	}
}

// WithEndpointsForRouter registers the groups endpoints on the router.
func (h *Handler) WithEndpointsForRouter(router *mux.Router) *mux.Router {
	router.HandleFunc("/groups", h.getAllGroups).Methods("GET", "OPTIONS")
	router.HandleFunc("/groups", h.createGroup).Methods("POST", "OPTIONS")
	router.HandleFunc("/groups/{groupId}", h.getGroup).Methods("GET", "OPTIONS")
	router.HandleFunc("/groups/{groupId}", h.updateGroup).Methods("PUT", "OPTIONS")
	router.HandleFunc("/groups/{groupId}", h.deleteGroup).Methods("DELETE", "OPTIONS")
	router.HandleFunc("/groups/{groupId}/peers", h.addPeers).Methods("POST", "OPTIONS")
	router.HandleFunc("/groups/{groupId}/peers", h.removePeers).Methods("DELETE", "OPTIONS")
	return router
}

func (h *Handler) getAllGroups(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	accountID, userID := userAuth.AccountId, userAuth.UserId

	var groups []*types.Group
	if name := r.URL.Query().Get("name"); name != "" {
		group, err := h.accountManager.GetGroupByName(r.Context(), name, accountID, userID)
		if err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
		groups = []*types.Group{group}
	} else {
		groups, err = h.accountManager.GetAllGroups(r.Context(), accountID, userID)
		if err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}
	}

	visible, err := h.visiblePeers(r.Context(), accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	response := make([]*apiv1alpha1.Group, 0, len(groups))
	for _, group := range groups {
		response = append(response, toGroupResponse(visible, group))
	}
	util.WriteJSONObject(r.Context(), w, response)
}

func (h *Handler) getGroup(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	accountID, userID := userAuth.AccountId, userAuth.UserId

	groupID, err := groupIDFromRequest(r)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	group, err := h.accountManager.GetGroup(r.Context(), accountID, groupID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	visible, err := h.visiblePeers(r.Context(), accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	writeGroup(r.Context(), w, visible, group)
}

func (h *Handler) createGroup(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	accountID, userID := userAuth.AccountId, userAuth.UserId

	var req apiv1alpha1.GroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	group, err := grouphandlers.NewGroup(groupInputFromRequest(req))
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	visible, err := h.visiblePeers(r.Context(), accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	if err := h.accountManager.CreateGroup(r.Context(), accountID, userID, group); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	writeGroup(r.Context(), w, visible, group)
}

func (h *Handler) updateGroup(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	accountID, userID := userAuth.AccountId, userAuth.UserId

	groupID, err := groupIDFromRequest(r)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	existing, err := grouphandlers.GetUpdatableGroup(r.Context(), h.accountManager, accountID, userID, groupID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	var req apiv1alpha1.GroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	group, err := grouphandlers.UpdatedGroup(existing, groupInputFromRequest(req))
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	visible, err := h.visiblePeers(r.Context(), accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	if err := h.accountManager.UpdateGroup(r.Context(), accountID, userID, group); err != nil {
		log.WithContext(r.Context()).Errorf("failed updating group %s under account %s %v", groupID, accountID, err)
		util.WriteError(r.Context(), err, w)
		return
	}

	writeGroup(r.Context(), w, visible, group)
}

func (h *Handler) deleteGroup(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	accountID, userID := userAuth.AccountId, userAuth.UserId

	groupID, err := groupIDFromRequest(r)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	if err := h.accountManager.DeleteGroup(r.Context(), accountID, userID, groupID); err != nil {
		writeDeleteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, util.EmptyObject{})
}

// writeDeleteError writes the error of a failed group deletion. A batch delete joins its errors,
// so the first one decides: a status error keeps its own code, anything else is a link error and
// a bad request.
func writeDeleteError(ctx context.Context, err error, w http.ResponseWriter) {
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok || len(joined.Unwrap()) == 0 {
		util.WriteError(ctx, err, w)
		return
	}

	first := joined.Unwrap()[0]
	if statusErr, ok := status.FromError(first); ok {
		util.WriteError(ctx, statusErr, w)
		return
	}
	util.WriteErrorResponse(first.Error(), http.StatusBadRequest, w)
}

func (h *Handler) addPeers(w http.ResponseWriter, r *http.Request) {
	h.changePeers(w, r, h.accountManager.AddPeersToGroup)
}

func (h *Handler) removePeers(w http.ResponseWriter, r *http.Request) {
	h.changePeers(w, r, h.accountManager.RemovePeersFromGroup)
}

type changePeersFunc func(ctx context.Context, accountID, userID, groupID string, peerIDs []string) (*types.Group, error)

func (h *Handler) changePeers(w http.ResponseWriter, r *http.Request, change changePeersFunc) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	accountID, userID := userAuth.AccountId, userAuth.UserId

	groupID, err := groupIDFromRequest(r)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	var req apiv1alpha1.GroupPeersRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	visible, err := h.visiblePeers(r.Context(), accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	group, err := change(r.Context(), accountID, userID, groupID, req.PeerIds)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	writeGroup(r.Context(), w, visible, group)
}

// writeGroup writes the group with the members the caller is allowed to see.
func writeGroup(ctx context.Context, w http.ResponseWriter, visible peerVisibility, group *types.Group) {
	util.WriteJSONObject(ctx, w, toGroupResponse(visible, group))
}

func groupIDFromRequest(r *http.Request) (string, error) {
	groupID := mux.Vars(r)["groupId"]
	if groupID == "" {
		return "", status.Errorf(status.InvalidArgument, "invalid group ID")
	}
	return groupID, nil
}

func groupInputFromRequest(req apiv1alpha1.GroupRequest) grouphandlers.GroupInput {
	in := grouphandlers.GroupInput{Name: req.Name}
	if req.Peers != nil {
		in.Peers = &req.Peers
	}
	if req.Resources != nil {
		resources := make([]grouphandlers.ResourceInput, 0, len(req.Resources))
		for _, res := range req.Resources {
			resources = append(resources, grouphandlers.ResourceInput{ID: res.Id, Type: string(res.Type)})
		}
		in.Resources = &resources
	}
	return in
}

// peerVisibility is the set of peers a caller may see. The zero value allows none.
type peerVisibility struct {
	all bool
	ids map[string]struct{}
}

func (v peerVisibility) allows(peerID string) bool {
	if v.all {
		return true
	}
	_, ok := v.ids[peerID]
	return ok
}

// visiblePeers resolves which peers the caller may see. Callers with peers read permission see
// every peer, others only their own. Any failure denies.
func (h *Handler) visiblePeers(ctx context.Context, accountID, userID string) (peerVisibility, error) {
	allowed, ctx, err := h.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Peers, operations.Read)
	if err != nil {
		return peerVisibility{}, status.NewPermissionValidationError(err)
	}
	if allowed {
		return peerVisibility{all: true}, nil
	}

	peers, err := h.accountManager.GetPeers(ctx, accountID, userID, "", "", "")
	if err != nil {
		return peerVisibility{}, err
	}

	ids := make(map[string]struct{}, len(peers))
	for _, peer := range peers {
		ids[peer.ID] = struct{}{}
	}
	return peerVisibility{ids: ids}, nil
}

// toGroupResponse converts a group to its API form, keeping only peers the caller may see.
func toGroupResponse(visible peerVisibility, group *types.Group) *apiv1alpha1.Group {
	issued := apiv1alpha1.GroupMinimumIssued(group.Issued)
	resp := &apiv1alpha1.Group{
		GroupMinimum: apiv1alpha1.GroupMinimum{
			Id:     group.ID,
			Name:   group.Name,
			Issued: &issued,
		},
		Peers:     make([]string, 0, len(group.Peers)),
		Resources: make([]apiv1alpha1.Resource, 0, len(group.Resources)),
	}

	seen := make(map[string]struct{}, len(group.Peers))
	for _, peerID := range group.Peers {
		if _, dup := seen[peerID]; dup {
			continue
		}
		seen[peerID] = struct{}{}

		if !visible.allows(peerID) {
			continue
		}
		resp.Peers = append(resp.Peers, peerID)
	}
	resp.PeersCount = len(resp.Peers)

	for _, res := range group.Resources {
		if res.ID == "" && res.Type == "" {
			continue
		}
		resp.Resources = append(resp.Resources, apiv1alpha1.Resource{
			Id:   res.ID,
			Type: apiv1alpha1.ResourceType(res.Type),
		})
	}
	resp.ResourcesCount = len(resp.Resources)

	return resp
}
