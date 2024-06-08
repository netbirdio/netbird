package http

import (
	"encoding/json"
	"net/http"
	"slices"

	"github.com/gorilla/mux"
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
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		log.Error(err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	groups, err := h.accountManager.GetAllGroups(account.Id, user.Id)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	groupsResponse := make([]*api.Group, 0, len(groups))
	for _, group := range groups {
		groupsResponse = append(groupsResponse, toGroupResponse(account, group))
	}

	util.WriteJSONObject(w, groupsResponse)
}

// UpdateGroup handles update to a group identified by a given ID
func (h *GroupsHandler) UpdateGroup(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	vars := mux.Vars(r)
	groupID, ok := vars["groupId"]
	if !ok {
		util.WriteError(status.Errorf(status.InvalidArgument, "group ID field is missing"), w)
		return
	}
	if len(groupID) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "group ID can't be empty"), w)
		return
	}

	eg, ok := account.Groups[groupID]
	if !ok {
		util.WriteError(status.Errorf(status.NotFound, "couldn't find group with ID %s", groupID), w)
		return
	}

	var req api.PutApiGroupsGroupIdJSONRequestBody
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	if req.Name == "" {
		util.WriteError(status.Errorf(status.InvalidArgument, "group name shouldn't be empty"), w)
		return
	}

	var peers []string
	if req.Peers == nil {
		peers = make([]string, 0)
	} else {
		peers = *req.Peers
	}

	allGroup, err := account.GetGroupAll()
	if err != nil {
		util.WriteError(err, w)
		return
	}

	if allGroup.ID == groupID {
		if len(peers) != len(allGroup.Peers) || req.Name != allGroup.Name {
			util.WriteError(status.Errorf(status.InvalidArgument, "updating group ALL is not allowed"), w)
			return
		}
		deduplicatedPeers := make(map[string]struct{})
		for _, peer := range peers {
			deduplicatedPeers[peer] = struct{}{}
		}
		if len(deduplicatedPeers) != len(peers) {
			util.WriteError(status.Errorf(status.InvalidArgument, "updating group ALL is not allowed"), w)
			return
		}
		for peer := range deduplicatedPeers {
			if slices.Contains(allGroup.Peers, peer) {
				continue
			}
			util.WriteError(status.Errorf(status.InvalidArgument, "updating group ALL is not allowed"), w)
			return
		}
	}

	group := nbgroup.Group{
		ID:                   groupID,
		Name:                 req.Name,
		Peers:                peers,
		Issued:               eg.Issued,
		IntegrationReference: eg.IntegrationReference,
		IPv6Enabled:          req.Ipv6Enabled,
	}

	if err := h.accountManager.SaveGroup(account.Id, user.Id, &group); err != nil {
		log.Errorf("failed updating group %s under account %s %v", groupID, account.Id, err)
		util.WriteError(err, w)
		return
	}

	util.WriteJSONObject(w, toGroupResponse(account, &group))
}

// CreateGroup handles group creation request
func (h *GroupsHandler) CreateGroup(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	var req api.PostApiGroupsJSONRequestBody
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	if req.Name == "" {
		util.WriteError(status.Errorf(status.InvalidArgument, "group name shouldn't be empty"), w)
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

	err = h.accountManager.SaveGroup(account.Id, user.Id, &group)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	util.WriteJSONObject(w, toGroupResponse(account, &group))
}

// DeleteGroup handles group deletion request
func (h *GroupsHandler) DeleteGroup(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}
	aID := account.Id

	groupID := mux.Vars(r)["groupId"]
	if len(groupID) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid group ID"), w)
		return
	}

	allGroup, err := account.GetGroupAll()
	if err != nil {
		util.WriteError(err, w)
		return
	}

	if allGroup.ID == groupID {
		util.WriteError(status.Errorf(status.InvalidArgument, "deleting group ALL is not allowed"), w)
		return
	}

	err = h.accountManager.DeleteGroup(aID, user.Id, groupID)
	if err != nil {
		_, ok := err.(*server.GroupLinkError)
		if ok {
			util.WriteErrorResponse(err.Error(), http.StatusBadRequest, w)
			return
		}
		util.WriteError(err, w)
		return
	}

	util.WriteJSONObject(w, emptyObject{})
}

// GetGroup returns a group
func (h *GroupsHandler) GetGroup(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	switch r.Method {
	case http.MethodGet:
		groupID := mux.Vars(r)["groupId"]
		if len(groupID) == 0 {
			util.WriteError(status.Errorf(status.InvalidArgument, "invalid group ID"), w)
			return
		}

		group, err := h.accountManager.GetGroup(account.Id, groupID, user.Id)
		if err != nil {
			util.WriteError(err, w)
			return
		}

		util.WriteJSONObject(w, toGroupResponse(account, group))
	default:
		util.WriteError(status.Errorf(status.NotFound, "HTTP method not found"), w)
		return
	}
}

func toGroupResponse(account *server.Account, group *nbgroup.Group) *api.Group {
	cache := make(map[string]api.PeerMinimum)
	gr := api.Group{
		Id:     group.ID,
		Name:   group.Name,
		Issued: (*api.GroupIssued)(&group.Issued),
		Ipv6Enabled: group.IPv6Enabled,
	}

	for _, pid := range group.Peers {
		_, ok := cache[pid]
		if !ok {
			peer, ok := account.Peers[pid]
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
