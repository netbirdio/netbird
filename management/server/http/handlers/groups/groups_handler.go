package groups

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/account"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"

	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

// handler is a handler that returns groups of the account
type handler struct {
	accountManager account.Manager
}

func AddEndpoints(accountManager account.Manager, router *mux.Router) {
	groupsHandler := newHandler(accountManager)
	router.HandleFunc("/groups", groupsHandler.getAllGroups).Methods("GET", "OPTIONS")
	router.HandleFunc("/groups", groupsHandler.createGroup).Methods("POST", "OPTIONS")
	router.HandleFunc("/groups/{groupId}", groupsHandler.updateGroup).Methods("PUT", "OPTIONS")
	router.HandleFunc("/groups/{groupId}", groupsHandler.getGroup).Methods("GET", "OPTIONS")
	router.HandleFunc("/groups/{groupId}", groupsHandler.deleteGroup).Methods("DELETE", "OPTIONS")
}

// newHandler creates a new groups handler
func newHandler(accountManager account.Manager) *handler {
	return &handler{
		accountManager: accountManager,
	}
}

// getAllGroups list for the account
func (h *handler) getAllGroups(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		log.WithContext(r.Context()).Error(err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}
	accountID, userID := userAuth.AccountId, userAuth.UserId

	// Check if filtering by name
	groupName := r.URL.Query().Get("name")
	if groupName != "" {
		// Get single group by name
		group, err := h.accountManager.GetGroupByName(r.Context(), groupName, accountID, userID)
		if err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}

		accountPeers, err := h.accountManager.GetPeers(r.Context(), accountID, userID, "", "", "")
		if err != nil {
			util.WriteError(r.Context(), err, w)
			return
		}

		// Return as array with single element to maintain API consistency
		groupsResponse := []*api.Group{toGroupResponse(accountPeers, group)}
		util.WriteJSONObject(r.Context(), w, groupsResponse)
		return
	}

	// Get all groups
	groups, err := h.accountManager.GetAllGroups(r.Context(), accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountPeers, err := h.accountManager.GetPeers(r.Context(), accountID, userID, "", "", "")
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
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId

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

	existingGroup, err := GetUpdatableGroup(r.Context(), h.accountManager, accountID, userID, groupID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	var req api.PutApiGroupsGroupIdJSONRequestBody
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	group, err := UpdatedGroup(existingGroup, groupInputFromAPI(req.Name, req.Peers, req.Resources))
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	if err := h.accountManager.UpdateGroup(r.Context(), accountID, userID, group); err != nil {
		log.WithContext(r.Context()).Errorf("failed updating group %s under account %s %v", groupID, accountID, err)
		util.WriteError(r.Context(), err, w)
		return
	}

	accountPeers, err := h.accountManager.GetPeers(r.Context(), accountID, userID, "", "", "")
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, toGroupResponse(accountPeers, group))
}

// createGroup handles group creation request
func (h *handler) createGroup(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId

	var req api.PostApiGroupsJSONRequestBody
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	group, err := NewGroup(groupInputFromAPI(req.Name, req.Peers, req.Resources))
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	err = h.accountManager.CreateGroup(r.Context(), accountID, userID, group)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountPeers, err := h.accountManager.GetPeers(r.Context(), accountID, userID, "", "", "")
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, toGroupResponse(accountPeers, group))
}

// deleteGroup handles group deletion request
func (h *handler) deleteGroup(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId

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
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId
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

	accountPeers, err := h.accountManager.GetPeers(r.Context(), accountID, userID, "", "", "")
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
		if resResp := res.ToAPIResponse(); resResp != nil {
			gr.Resources = append(gr.Resources, *resResp)
		}
	}

	gr.ResourcesCount = len(gr.Resources)

	return &gr
}

func groupInputFromAPI(name string, peers *[]string, resources *[]api.Resource) GroupInput {
	in := GroupInput{Name: name, Peers: peers}
	if resources == nil {
		return in
	}

	converted := make([]ResourceInput, 0, len(*resources))
	for _, res := range *resources {
		converted = append(converted, ResourceInput{ID: res.Id, Type: string(res.Type)})
	}
	in.Resources = &converted
	return in
}
