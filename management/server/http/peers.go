package http

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/status"
	"net/http"
)

// Peers is a handler that returns peers of the account
type Peers struct {
	accountManager server.AccountManager
	authAudience   string
	jwtExtractor   jwtclaims.ClaimsExtractor
}

func NewPeers(accountManager server.AccountManager, authAudience string) *Peers {
	return &Peers{
		accountManager: accountManager,
		authAudience:   authAudience,
		jwtExtractor:   *jwtclaims.NewClaimsExtractor(nil),
	}
}

func (h *Peers) updatePeer(account *server.Account, peer *server.Peer, w http.ResponseWriter, r *http.Request) {
	req := &api.PutApiPeersIdJSONBody{}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteError(status.Errorf(status.InvalidArgument, "couldn't parse JSON request"), w)
		return
	}

	update := &server.Peer{Key: peer.Key, SSHEnabled: req.SshEnabled, Name: req.Name}
	peer, err = h.accountManager.UpdatePeer(account.Id, update)
	if err != nil {
		util.WriteError(err, w)
		return
	}
	util.WriteJSONObject(w, toPeerResponse(peer, account))
}

func (h *Peers) deletePeer(accountId string, peer *server.Peer, w http.ResponseWriter, r *http.Request) {
	_, err := h.accountManager.DeletePeer(accountId, peer.Key)
	if err != nil {
		util.WriteError(err, w)
		return
	}
	util.WriteJSONObject(w, "")
}

func (h *Peers) HandlePeer(w http.ResponseWriter, r *http.Request) {
	claims := h.jwtExtractor.ExtractClaimsFromRequestContext(r, h.authAudience)
	account, _, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}
	vars := mux.Vars(r)
	peerId := vars["id"] //effectively peer IP address
	if len(peerId) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid peer ID"), w)
		return
	}

	peer, err := h.accountManager.GetPeerByIP(account.Id, peerId)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	switch r.Method {
	case http.MethodDelete:
		h.deletePeer(account.Id, peer, w, r)
		return
	case http.MethodPut:
		h.updatePeer(account, peer, w, r)
		return
	case http.MethodGet:
		util.WriteJSONObject(w, toPeerResponse(peer, account))
		return

	default:
		util.WriteError(status.Errorf(status.NotFound, "unknown METHOD"), w)
	}

}

func (h *Peers) GetPeers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		claims := h.jwtExtractor.ExtractClaimsFromRequestContext(r, h.authAudience)
		account, user, err := h.accountManager.GetAccountFromToken(claims)
		if err != nil {
			util.WriteError(err, w)
			return
		}

		peers, err := h.accountManager.GetPeers(account.Id, user.Id)
		if err != nil {
			util.WriteError(err, w)
			return
		}

		respBody := []*api.Peer{}
		for _, peer := range peers {
			respBody = append(respBody, toPeerResponse(peer, account))
		}
		util.WriteJSONObject(w, respBody)
		return
	default:
		util.WriteError(status.Errorf(status.NotFound, "unknown METHOD"), w)
	}
}

func toPeerResponse(peer *server.Peer, account *server.Account) *api.Peer {
	var groupsInfo []api.GroupMinimum
	groupsChecked := make(map[string]struct{})
	for _, group := range account.Groups {
		_, ok := groupsChecked[group.ID]
		if ok {
			continue
		}
		groupsChecked[group.ID] = struct{}{}
		for _, pk := range group.Peers {
			if pk == peer.Key {
				info := api.GroupMinimum{
					Id:         group.ID,
					Name:       group.Name,
					PeersCount: len(group.Peers),
				}
				groupsInfo = append(groupsInfo, info)
				break
			}
		}
	}
	return &api.Peer{
		Id:         peer.IP.String(),
		Name:       peer.Name,
		Ip:         peer.IP.String(),
		Connected:  peer.Status.Connected,
		LastSeen:   peer.Status.LastSeen,
		Os:         fmt.Sprintf("%s %s", peer.Meta.OS, peer.Meta.Core),
		Version:    peer.Meta.WtVersion,
		Groups:     groupsInfo,
		SshEnabled: peer.SSHEnabled,
		Hostname:   peer.Meta.Hostname,
		UserId:     &peer.UserID,
		UiVersion:  &peer.Meta.UIVersion,
		DnsLabel:   peer.DNSLabel,
	}
}
