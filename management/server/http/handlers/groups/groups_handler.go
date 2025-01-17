package groups

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/http/configs"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/status"
)

// handler is a handler that returns groups of the account
type handler struct {
	accountManager  server.AccountManager
	claimsExtractor *jwtclaims.ClaimsExtractor
}

func AddEndpoints(accountManager server.AccountManager, authCfg configs.AuthCfg, router *mux.Router) {
	groupsHandler := newHandler(accountManager, authCfg)
	router.HandleFunc("/groups", groupsHandler.getAllGroups).Methods("GET", "OPTIONS")
	router.HandleFunc("/groups", groupsHandler.createGroup).Methods("POST", "OPTIONS")
	router.HandleFunc("/groups/{groupId}", groupsHandler.updateGroup).Methods("PUT", "OPTIONS")
	router.HandleFunc("/groups/{groupId}", groupsHandler.getGroup).Methods("GET", "OPTIONS")
	router.HandleFunc("/groups/{groupId}", groupsHandler.deleteGroup).Methods("DELETE", "OPTIONS")
}

// newHandler creates a new groups handler
func newHandler(accountManager server.AccountManager, authCfg configs.AuthCfg) *handler {
	return &handler{
		accountManager: accountManager,
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithAudience(authCfg.Audience),
			jwtclaims.WithUserIDClaim(authCfg.UserIDClaim),
		),
	}
}

// getAllGroups list for the account
func (h *handler) getAllGroups(w http.ResponseWriter, r *http.Request) {
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

	accountPeers, err := h.accountManager.GetPeers(r.Context(), accountID, userID)
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

// updateGroup handles update to a group identified by a given ID
func (h *handler) updateGroup(w http.ResponseWriter, r *http.Request) {
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

	resources := make([]types.Resource, 0)
	if req.Resources != nil {
		for _, res := range *req.Resources {
			resource := types.Resource{}
			resource.FromAPIRequest(&res)
			resources = append(resources, resource)
		}
	}

	group := types.Group{
		ID:                   groupID,
		Name:                 req.Name,
		Peers:                peers,
		Resources:            resources,
		Issued:               existingGroup.Issued,
		IntegrationReference: existingGroup.IntegrationReference,
	}

	if err := h.accountManager.SaveGroup(r.Context(), accountID, userID, &group); err != nil {
		log.WithContext(r.Context()).Errorf("failed updating group %s under account %s %v", groupID, accountID, err)
		util.WriteError(r.Context(), err, w)
		return
	}

	accountPeers, err := h.accountManager.GetPeers(r.Context(), accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, toGroupResponse(accountPeers, &group))
}

// createGroup handles group creation request
func (h *handler) createGroup(w http.ResponseWriter, r *http.Request) {
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

	resources := make([]types.Resource, 0)
	if req.Resources != nil {
		for _, res := range *req.Resources {
			resource := types.Resource{}
			resource.FromAPIRequest(&res)
			resources = append(resources, resource)
		}
	}

	group := types.Group{
		Name:      req.Name,
		Peers:     peers,
		Resources: resources,
		Issued:    types.GroupIssuedAPI,
	}

	err = h.accountManager.SaveGroup(r.Context(), accountID, userID, &group)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountPeers, err := h.accountManager.GetPeers(r.Context(), accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, toGroupResponse(accountPeers, &group))
}

// deleteGroup handles group deletion request
func (h *handler) deleteGroup(w http.ResponseWriter, r *http.Request) {
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
		wrappedErr, ok := err.(interface{ Unwrap() []error })
		if ok && len(wrappedErr.Unwrap()) > 0 {
			err = wrappedErr.Unwrap()[0]
			util.WriteErrorResponse(err.Error(), http.StatusBadRequest, w)
			return
		}
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, util.EmptyObject{})
}

// getGroup returns a group
func (h *handler) getGroup(w http.ResponseWriter, r *http.Request) {
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

	accountPeers, err := h.accountManager.GetPeers(r.Context(), accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, toGroupResponse(accountPeers, group))

}

func toGroupResponse(peers []*nbpeer.Peer, group *types.Group) *api.Group {
	peersMap := make(map[string]*nbpeer.Peer, len(peers))
	for _, peer := range peers {
		peersMap[peer.ID] = peer
	}

	peerCache := make(map[string]api.PeerMinimum)
	gr := api.Group{
		Id:     group.ID,
		Name:   group.Name,
		Issued: (*api.GroupIssued)(&group.Issued),
	}

	for _, pid := range group.Peers {
		_, ok := peerCache[pid]
		if !ok {
			peer, ok := peersMap[pid]
			if !ok {
				continue
			}
			peerResp := api.PeerMinimum{
				Id:   peer.ID,
				Name: peer.Name,
			}
			peerCache[pid] = peerResp
			gr.Peers = append(gr.Peers, peerResp)
		}
	}

	gr.PeersCount = len(gr.Peers)

	for _, res := range group.Resources {
		resResp := res.ToAPIResponse()
		gr.Resources = append(gr.Resources, *resResp)
	}

	gr.ResourcesCount = len(gr.Resources)

	return &gr
}
