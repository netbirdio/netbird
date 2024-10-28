package http

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server"
	nbgroup "github.com/netbirdio/netbird/management/server/group"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/status"
)

// GroupsHandler is a handler that returns groups of the account
type GroupsHandler struct {
	accountManager  server.AccountManager
	claimsExtractor *jwtclaims.ClaimsExtractor
}

// NewGroupsHandler creates a new GroupsHandler HTTP handler
func NewGroupsHandler(accountManager server.AccountManager, authCfg AuthCfg) *GroupsHandler {
	return &GroupsHandler{
		accountManager: accountManager,
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithAudience(authCfg.Audience),
			jwtclaims.WithUserIDClaim(authCfg.UserIDClaim),
		),
	}
}

// GetAllGroups list for the account
func (h *GroupsHandler) GetAllGroups(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.accountManager.GetAccountIDFromToken(r.Context(), claims)
	if err != nil {
		log.WithContext(r.Context()).Error(err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	groups, err := h.accountManager.GetAllGroups(r.Context(), accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountPeers, err := h.accountManager.GetUserPeers(r.Context(), accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	groupsResponse := make([]*api.Group, 0, len(groups))
	for _, group := range groups {
		groupsResponse = append(groupsResponse, toGroupResponse(accountPeers, group))
	}

	util.WriteJSONObject(r.Context(), w, groupsResponse)
}

// UpdateGroup handles update to a group identified by a given ID
func (h *GroupsHandler) UpdateGroup(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.accountManager.GetAccountIDFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	vars := mux.Vars(r)
	groupID, ok := vars["groupId"]
	if !ok {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "group ID field is missing"), w)
		return
	}
	if len(groupID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "group ID can't be empty"), w)
		return
	}

	existingGroup, err := h.accountManager.GetGroup(r.Context(), accountID, groupID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	allGroup, err := h.accountManager.GetGroupByName(r.Context(), "All", accountID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	if allGroup.ID == groupID {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "updating group ALL is not allowed"), w)
		return
	}

	var req api.PutApiGroupsGroupIdJSONRequestBody
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	if req.Name == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "group name shouldn't be empty"), w)
		return
	}

	var peers []string
	if req.Peers == nil {
		peers = make([]string, 0)
	} else {
		peers = *req.Peers
	}
	group := nbgroup.Group{
		ID:                   groupID,
		Name:                 req.Name,
		Peers:                peers,
		Issued:               existingGroup.Issued,
		IntegrationReference: existingGroup.IntegrationReference,
	}

	if err := h.accountManager.SaveGroup(r.Context(), accountID, userID, &group); err != nil {
		log.WithContext(r.Context()).Errorf("failed updating group %s under account %s %v", groupID, accountID, err)
		util.WriteError(r.Context(), err, w)
		return
	}

	accountPeers, err := h.accountManager.GetUserPeers(r.Context(), accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, toGroupResponse(accountPeers, &group))
}

// CreateGroup handles group creation request
func (h *GroupsHandler) CreateGroup(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.accountManager.GetAccountIDFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	var req api.PostApiGroupsJSONRequestBody
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	if req.Name == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "group name shouldn't be empty"), w)
		return
	}

	var peers []string
	if req.Peers == nil {
		peers = make([]string, 0)
	} else {
		peers = *req.Peers
	}
	group := nbgroup.Group{
		Name:   req.Name,
		Peers:  peers,
		Issued: nbgroup.GroupIssuedAPI,
	}

	err = h.accountManager.SaveGroup(r.Context(), accountID, userID, &group)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountPeers, err := h.accountManager.GetUserPeers(r.Context(), accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, toGroupResponse(accountPeers, &group))
}

// DeleteGroup handles group deletion request
func (h *GroupsHandler) DeleteGroup(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.accountManager.GetAccountIDFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	groupID := mux.Vars(r)["groupId"]
	if len(groupID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid group ID"), w)
		return
	}

	err = h.accountManager.DeleteGroup(r.Context(), accountID, userID, groupID)
	if err != nil {
		_, ok := err.(*server.GroupLinkError)
		if ok {
			util.WriteErrorResponse(err.Error(), http.StatusBadRequest, w)
			return
		}
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, emptyObject{})
}

// GetGroup returns a group
func (h *GroupsHandler) GetGroup(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.accountManager.GetAccountIDFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	groupID := mux.Vars(r)["groupId"]
	if len(groupID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid group ID"), w)
		return
	}

	group, err := h.accountManager.GetGroup(r.Context(), accountID, groupID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountPeers, err := h.accountManager.GetUserPeers(r.Context(), accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, toGroupResponse(accountPeers, group))

}

func toGroupResponse(peers []*nbpeer.Peer, group *nbgroup.Group) *api.Group {
	peersMap := make(map[string]*nbpeer.Peer, len(peers))
	for _, peer := range peers {
		peersMap[peer.ID] = peer
	}

	cache := make(map[string]api.PeerMinimum)
	gr := api.Group{
		Id:     group.ID,
		Name:   group.Name,
		Issued: (*api.GroupIssued)(&group.Issued),
	}

	for _, pid := range group.Peers {
		_, ok := cache[pid]
		if !ok {
			peer, ok := peersMap[pid]
			if !ok {
				continue
			}
			peerResp := api.PeerMinimum{
				Id:   peer.ID,
				Name: peer.Name,
			}
			cache[pid] = peerResp
			gr.Peers = append(gr.Peers, peerResp)
		}
	}

	gr.PeersCount = len(gr.Peers)

	return &gr
}
