package handler

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/rs/xid"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

// GroupResponse is a response sent to the client
type GroupResponse struct {
	ID    string
	Name  string
	Peers []GroupPeerResponse `json:",omitempty"`
}

// GroupPeerResponse is a response sent to the client
type GroupPeerResponse struct {
	Key  string
	Name string
}

// GroupRequest to create or update group
type GroupRequest struct {
	ID    string
	Name  string
	Peers []string
}

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
	account, err := h.getGroupAccount(r)
	if err != nil {
		log.Error(err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	var groups []*GroupResponse
	for _, g := range account.Groups {
		groups = append(groups, toGroupResponse(account, g))
	}

	writeJSONObject(w, groups)
}

func (h *Groups) CreateOrUpdateGroupHandler(w http.ResponseWriter, r *http.Request) {
	account, err := h.getGroupAccount(r)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	var req GroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if r.Method == http.MethodPost {
		req.ID = xid.New().String()
	}

	group := server.Group{
		ID:    req.ID,
		Name:  req.Name,
		Peers: req.Peers,
	}

	if err := h.accountManager.SaveGroup(account.Id, &group); err != nil {
		log.Errorf("failed updating group %s under account %s %v", req.ID, account.Id, err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	writeJSONObject(w, toGroupResponse(account, &group))
}

func (h *Groups) DeleteGroupHandler(w http.ResponseWriter, r *http.Request) {
	account, err := h.getGroupAccount(r)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}
	aID := account.Id

	gID := mux.Vars(r)["id"]
	if len(gID) == 0 {
		http.Error(w, "invalid group ID", http.StatusBadRequest)
		return
	}

	if err := h.accountManager.DeleteGroup(aID, gID); err != nil {
		log.Errorf("failed delete group %s under account %s %v", gID, aID, err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	writeJSONObject(w, "")
}

func (h *Groups) GetGroupHandler(w http.ResponseWriter, r *http.Request) {
	account, err := h.getGroupAccount(r)
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

func (h *Groups) getGroupAccount(r *http.Request) (*server.Account, error) {
	jwtClaims := h.jwtExtractor.ExtractClaimsFromRequestContext(r, h.authAudience)

	account, err := h.accountManager.GetAccountWithAuthorizationClaims(jwtClaims)
	if err != nil {
		return nil, fmt.Errorf("failed getting account of a user %s: %v", jwtClaims.UserId, err)
	}

	return account, nil
}

func toGroupResponse(account *server.Account, group *server.Group) *GroupResponse {
	cache := make(map[string]GroupPeerResponse)
	gr := GroupResponse{
		ID:   group.ID,
		Name: group.Name,
	}

	for _, pid := range group.Peers {
		peerResp, ok := cache[pid]
		if !ok {
			peer, ok := account.Peers[pid]
			if !ok {
				continue
			}
			peerResp = GroupPeerResponse{
				Key:  peer.Key,
				Name: peer.Name,
			}
			cache[pid] = peerResp
		}
		gr.Peers = append(gr.Peers, peerResp)
	}

	return &gr
}
