package http

import (
	"encoding/json"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/status"
	"net/http"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/rs/xid"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

// Groups is a handler that returns groups of the account
type Groups struct {
	jwtExtractor   jwtclaims.ClaimsExtractor
	accountManager server.AccountManager
	authAudience   string
}

func NewGroups(accountManager server.AccountManager, authAudience string) *Groups {
	return &Groups{
		accountManager: accountManager,
		authAudience:   authAudience,
		jwtExtractor:   *jwtclaims.NewClaimsExtractor(nil),
	}
}

// GetAllGroupsHandler list for the account
func (h *Groups) GetAllGroupsHandler(w http.ResponseWriter, r *http.Request) {
	claims := h.jwtExtractor.ExtractClaimsFromRequestContext(r, h.authAudience)
	account, _, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		log.Error(err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	var groups []*api.Group
	for _, g := range account.Groups {
		groups = append(groups, toGroupResponse(account, g))
	}

	util.WriteJSONObject(w, groups)
}

// UpdateGroupHandler handles update to a group identified by a given ID
func (h *Groups) UpdateGroupHandler(w http.ResponseWriter, r *http.Request) {
	claims := h.jwtExtractor.ExtractClaimsFromRequestContext(r, h.authAudience)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	vars := mux.Vars(r)
	groupID, ok := vars["id"]
	if !ok {
		util.WriteError(status.Errorf(status.InvalidArgument, "group ID field is missing"), w)
		return
	}
	if len(groupID) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "group ID can't be empty"), w)
		return
	}

	_, ok = account.Groups[groupID]
	if !ok {
		util.WriteError(status.Errorf(status.NotFound, "couldn't find group with ID %s", groupID), w)
		return
	}

	allGroup, err := account.GetGroupAll()
	if err != nil {
		util.WriteError(err, w)
		return
	}
	if allGroup.ID == groupID {
		util.WriteError(status.Errorf(status.InvalidArgument, "updating group ALL is not allowed"), w)
		return
	}

	var req api.PutApiGroupsIdJSONRequestBody
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	if *req.Name == "" {
		util.WriteError(status.Errorf(status.InvalidArgument, "group name shouldn't be empty"), w)
		return
	}

	group := server.Group{
		ID:    groupID,
		Name:  *req.Name,
		Peers: peerIPsToKeys(account, req.Peers),
	}

	if err := h.accountManager.SaveGroup(account.Id, user.Id, &group); err != nil {
		log.Errorf("failed updating group %s under account %s %v", groupID, account.Id, err)
		util.WriteError(err, w)
		return
	}

	util.WriteJSONObject(w, toGroupResponse(account, &group))
}

// PatchGroupHandler handles patch updates to a group identified by a given ID
func (h *Groups) PatchGroupHandler(w http.ResponseWriter, r *http.Request) {
	claims := h.jwtExtractor.ExtractClaimsFromRequestContext(r, h.authAudience)
	account, _, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	vars := mux.Vars(r)
	groupID := vars["id"]
	if len(groupID) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid group ID"), w)
		return
	}

	_, ok := account.Groups[groupID]
	if !ok {
		util.WriteError(status.Errorf(status.NotFound, "couldn't find group ID %s", groupID), w)
		return
	}

	allGroup, err := account.GetGroupAll()
	if err != nil {
		util.WriteError(err, w)
		return
	}

	if allGroup.ID == groupID {
		util.WriteError(status.Errorf(status.InvalidArgument, "updating group ALL is not allowed"), w)
		return
	}

	var req api.PatchApiGroupsIdJSONRequestBody
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	if len(req) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "no patch instruction received"), w)
		return
	}

	var operations []server.GroupUpdateOperation

	for _, patch := range req {
		switch patch.Path {
		case api.GroupPatchOperationPathName:
			if patch.Op != api.GroupPatchOperationOpReplace {
				util.WriteError(status.Errorf(status.InvalidArgument,
					"name field only accepts replace operation, got %s", patch.Op), w)
				return
			}

			if len(patch.Value) == 0 || patch.Value[0] == "" {
				util.WriteError(status.Errorf(status.InvalidArgument, "group name shouldn't be empty"), w)
				return
			}

			operations = append(operations, server.GroupUpdateOperation{
				Type:   server.UpdateGroupName,
				Values: patch.Value,
			})
		case api.GroupPatchOperationPathPeers:
			switch patch.Op {
			case api.GroupPatchOperationOpReplace:
				peerKeys := peerIPsToKeys(account, &patch.Value)
				operations = append(operations, server.GroupUpdateOperation{
					Type:   server.UpdateGroupPeers,
					Values: peerKeys,
				})
			case api.GroupPatchOperationOpRemove:
				peerKeys := peerIPsToKeys(account, &patch.Value)
				operations = append(operations, server.GroupUpdateOperation{
					Type:   server.RemovePeersFromGroup,
					Values: peerKeys,
				})
			case api.GroupPatchOperationOpAdd:
				peerKeys := peerIPsToKeys(account, &patch.Value)
				operations = append(operations, server.GroupUpdateOperation{
					Type:   server.InsertPeersToGroup,
					Values: peerKeys,
				})
			default:
				util.WriteError(status.Errorf(status.InvalidArgument,
					"invalid operation, \"%v\", for Peers field", patch.Op), w)
				return
			}
		default:
			util.WriteError(status.Errorf(status.InvalidArgument, "invalid patch path"), w)
			return
		}
	}

	group, err := h.accountManager.UpdateGroup(account.Id, groupID, operations)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	util.WriteJSONObject(w, toGroupResponse(account, group))
}

// CreateGroupHandler handles group creation request
func (h *Groups) CreateGroupHandler(w http.ResponseWriter, r *http.Request) {
	claims := h.jwtExtractor.ExtractClaimsFromRequestContext(r, h.authAudience)
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

	group := server.Group{
		ID:    xid.New().String(),
		Name:  req.Name,
		Peers: peerIPsToKeys(account, req.Peers),
	}

	err = h.accountManager.SaveGroup(account.Id, user.Id, &group)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	util.WriteJSONObject(w, toGroupResponse(account, &group))
}

// DeleteGroupHandler handles group deletion request
func (h *Groups) DeleteGroupHandler(w http.ResponseWriter, r *http.Request) {
	claims := h.jwtExtractor.ExtractClaimsFromRequestContext(r, h.authAudience)
	account, _, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}
	aID := account.Id

	groupID := mux.Vars(r)["id"]
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

	err = h.accountManager.DeleteGroup(aID, groupID)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	util.WriteJSONObject(w, "")
}

// GetGroupHandler returns a group
func (h *Groups) GetGroupHandler(w http.ResponseWriter, r *http.Request) {
	claims := h.jwtExtractor.ExtractClaimsFromRequestContext(r, h.authAudience)
	account, _, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	switch r.Method {
	case http.MethodGet:
		groupID := mux.Vars(r)["id"]
		if len(groupID) == 0 {
			util.WriteError(status.Errorf(status.InvalidArgument, "invalid group ID"), w)
			return
		}

		group, err := h.accountManager.GetGroup(account.Id, groupID)
		if err != nil {
			util.WriteError(err, w)
			return
		}

		util.WriteJSONObject(w, toGroupResponse(account, group))
	default:
		if err != nil {
			util.WriteError(status.Errorf(status.NotFound, "HTTP method not found"), w)
			return
		}
	}
}

func peerIPsToKeys(account *server.Account, peerIPs *[]string) []string {
	var mappedPeerKeys []string
	if peerIPs == nil {
		return mappedPeerKeys
	}

	peersChecked := make(map[string]struct{})

	for _, requestPeersIP := range *peerIPs {
		_, ok := peersChecked[requestPeersIP]
		if ok {
			continue
		}
		peersChecked[requestPeersIP] = struct{}{}
		for _, accountPeer := range account.Peers {
			if accountPeer.IP.String() == requestPeersIP {
				mappedPeerKeys = append(mappedPeerKeys, accountPeer.Key)
			}
		}
	}
	return mappedPeerKeys
}

func toGroupResponse(account *server.Account, group *server.Group) *api.Group {
	cache := make(map[string]api.PeerMinimum)
	gr := api.Group{
		Id:         group.ID,
		Name:       group.Name,
		PeersCount: len(group.Peers),
	}

	for _, pid := range group.Peers {
		_, ok := cache[pid]
		if !ok {
			peer, ok := account.Peers[pid]
			if !ok {
				continue
			}
			peerResp := api.PeerMinimum{
				Id:   peer.IP.String(),
				Name: peer.Name,
			}
			cache[pid] = peerResp
			gr.Peers = append(gr.Peers, peerResp)
		}
	}
	return &gr
}
