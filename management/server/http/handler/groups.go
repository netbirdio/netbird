package handler

import (
	"encoding/json"
	"fmt"
	"github.com/netbirdio/netbird/management/server/http/api"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	account, err := getJWTAccount(h.accountManager, h.jwtExtractor, h.authAudience, r)
	if err != nil {
		log.Error(err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	var groups []*api.Group
	for _, g := range account.Groups {
		groups = append(groups, toGroupResponse(account, g))
	}

	writeJSONObject(w, groups)
}

// UpdateGroupHandler handles update to a group identified by a given ID
func (h *Groups) UpdateGroupHandler(w http.ResponseWriter, r *http.Request) {
	account, err := getJWTAccount(h.accountManager, h.jwtExtractor, h.authAudience, r)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	vars := mux.Vars(r)
	groupID := vars["id"]
	if len(groupID) == 0 {
		http.Error(w, "invalid group Id", http.StatusBadRequest)
		return
	}

	_, ok := account.Groups[groupID]
	if !ok {
		http.Error(w, fmt.Sprintf("couldn't find group id %s", groupID), http.StatusNotFound)
		return
	}

	allGroup, err := account.GetGroupAll()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if allGroup.ID == groupID {
		http.Error(w, "updating group ALL is not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req api.PutApiGroupsIdJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	group := server.Group{
		ID:    groupID,
		Name:  *req.Name,
		Peers: peerIPsToKeys(account, req.Peers),
	}

	if err := h.accountManager.SaveGroup(account.Id, &group); err != nil {
		log.Errorf("failed updating group %s under account %s %v", groupID, account.Id, err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	writeJSONObject(w, toGroupResponse(account, &group))
}

// PatchGroupHandler handles patch updates to a group identified by a given ID
func (h *Groups) PatchGroupHandler(w http.ResponseWriter, r *http.Request) {
	account, err := getJWTAccount(h.accountManager, h.jwtExtractor, h.authAudience, r)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	vars := mux.Vars(r)
	groupID := vars["id"]
	if len(groupID) == 0 {
		http.Error(w, "invalid group Id", http.StatusBadRequest)
		return
	}

	_, ok := account.Groups[groupID]
	if !ok {
		http.Error(w, fmt.Sprintf("couldn't find group id %s", groupID), http.StatusNotFound)
		return
	}

	allGroup, err := account.GetGroupAll()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if allGroup.ID == groupID {
		http.Error(w, "updating group ALL is not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req api.PatchApiGroupsIdJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if len(req) == 0 {
		http.Error(w, "no patch instruction received", http.StatusBadRequest)
		return
	}

	var operations []server.GroupUpdateOperation

	for _, patch := range req {
		switch patch.Path {
		case api.GroupPatchOperationPathName:
			if patch.OP != api.GroupPatchOperationOPReplace {
				http.Error(w, fmt.Sprintf("Name field only accepts replace operation, got %s", patch.OP),
					http.StatusBadRequest)
				return
			}
			operations = append(operations, server.GroupUpdateOperation{
				Type:   server.UpdateGroupName,
				Values: patch.Value,
			})
		case api.GroupPatchOperationPathPeers:
			switch patch.OP {
			case api.GroupPatchOperationOPReplace:
				operations = append(operations, server.GroupUpdateOperation{
					Type:   server.UpdateGroupPeers,
					Values: patch.Value,
				})
			case api.GroupPatchOperationOPRemove:
				peerKeys := peerIPsToKeys(account, &patch.Value)
				operations = append(operations, server.GroupUpdateOperation{
					Type:   server.RemovePeersFromGroup,
					Values: peerKeys,
				})
			case api.GroupPatchOperationOPAdd:
				peerKeys := peerIPsToKeys(account, &patch.Value)
				operations = append(operations, server.GroupUpdateOperation{
					Type:   server.InsertPeersToGroup,
					Values: peerKeys,
				})
			default:
				http.Error(w, "invalid operation, \"%s\", for Peers field", http.StatusBadRequest)
				return
			}
		default:
			http.Error(w, "invalid patch path", http.StatusBadRequest)
			return
		}
	}

	group, err := h.accountManager.UpdateGroup(account.Id, groupID, operations)

	if err != nil {
		errStatus, ok := status.FromError(err)
		if ok && errStatus.Code() == codes.Internal {
			http.Error(w, errStatus.String(), http.StatusInternalServerError)
			return
		}

		if ok && errStatus.Code() == codes.NotFound {
			http.Error(w, errStatus.String(), http.StatusNotFound)
			return
		}

		log.Errorf("failed updating group %s under account %s %v", groupID, account.Id, err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	writeJSONObject(w, toGroupResponse(account, group))
}

// CreateGroupHandler handles group creation request
func (h *Groups) CreateGroupHandler(w http.ResponseWriter, r *http.Request) {
	account, err := getJWTAccount(h.accountManager, h.jwtExtractor, h.authAudience, r)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	var req api.PostApiGroupsJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	group := server.Group{
		ID:    xid.New().String(),
		Name:  req.Name,
		Peers: peerIPsToKeys(account, req.Peers),
	}

	if err := h.accountManager.SaveGroup(account.Id, &group); err != nil {
		log.Errorf("failed creating group \"%s\" under account %s %v", req.Name, account.Id, err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	writeJSONObject(w, toGroupResponse(account, &group))
}

// DeleteGroupHandler handles group deletion request
func (h *Groups) DeleteGroupHandler(w http.ResponseWriter, r *http.Request) {
	account, err := getJWTAccount(h.accountManager, h.jwtExtractor, h.authAudience, r)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}
	aID := account.Id

	groupID := mux.Vars(r)["id"]
	if len(groupID) == 0 {
		http.Error(w, "invalid group ID", http.StatusBadRequest)
		return
	}

	allGroup, err := account.GetGroupAll()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if allGroup.ID == groupID {
		http.Error(w, "deleting group ALL is not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := h.accountManager.DeleteGroup(aID, groupID); err != nil {
		log.Errorf("failed delete group %s under account %s %v", groupID, aID, err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	writeJSONObject(w, "")
}

// GetGroupHandler returns a group
func (h *Groups) GetGroupHandler(w http.ResponseWriter, r *http.Request) {
	account, err := getJWTAccount(h.accountManager, h.jwtExtractor, h.authAudience, r)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	switch r.Method {
	case http.MethodGet:
		groupID := mux.Vars(r)["id"]
		if len(groupID) == 0 {
			http.Error(w, "invalid group ID", http.StatusBadRequest)
			return
		}

		group, err := h.accountManager.GetGroup(account.Id, groupID)
		if err != nil {
			http.Error(w, "group not found", http.StatusNotFound)
			return
		}

		writeJSONObject(w, toGroupResponse(account, group))
	default:
		http.Error(w, "", http.StatusNotFound)
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
		ID:         group.ID,
		Name:       group.Name,
		PeersCount: len(group.Peers),
	}

	for _, pid := range group.Peers {
		peerResp, ok := cache[pid]
		if !ok {
			peer, ok := account.Peers[pid]
			if !ok {
				continue
			}
			peerResp = api.PeerMinimum{
				ID:   peer.IP.String(),
				Name: peer.Name,
			}
			cache[pid] = peerResp
		}
		gr.Peers = append(gr.Peers, peerResp)
	}

	return &gr
}
