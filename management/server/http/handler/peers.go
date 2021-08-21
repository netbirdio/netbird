package handler

import (
	"encoding/json"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/management/server"
	"net/http"
	"time"
)

//Peers is a handler that returns peers of the account
type Peers struct {
	accountManager *server.AccountManager
}

//PeerResponse is a response sent to the client
type PeerResponse struct {
	Name      string
	IP        string
	Connected bool
	LastSeen  time.Time
	OS        string
}

//PeerRequest is a request sent by the client
type PeerRequest struct {
	Name string
}

func NewPeers(accountManager *server.AccountManager) *Peers {
	return &Peers{
		accountManager: accountManager,
	}
}
func (h *Peers) HandlePeer(w http.ResponseWriter, r *http.Request) {
	accountId := extractAccountIdFromRequestContext(r)
	vars := mux.Vars(r)
	peerId := vars["id"] //effectively peer IP address
	if len(peerId) == 0 {
		http.Error(w, "invalid peer Id", http.StatusBadRequest)
		return
	}

	peer, err := h.accountManager.GetPeerByIP(accountId, peerId)
	if err != nil {
		http.Error(w, "peer not found", http.StatusNotFound)
		return
	}

	switch r.Method {
	case http.MethodDelete:
		_, err = h.accountManager.DeletePeer(accountId, peer.Key)
		if err != nil {
			log.Errorf("failed deleteing peer %s, %v", peer.IP, err)
			http.Redirect(w, r, "/", http.StatusInternalServerError)
			return
		}
		return
	case http.MethodPost:
		req := &PeerRequest{}
		err = json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		peer, err = h.accountManager.RenamePeer(accountId, peer.Key, req.Name)
		if err != nil {
			log.Errorf("failed updating peer %s, %v", peerId, err)
			http.Redirect(w, r, "/", http.StatusInternalServerError)
			return
		}
		writeJSONObject(w, toPeerResponse(peer))
		return
	case http.MethodGet:
		writeJSONObject(w, toPeerResponse(peer))
		return

	default:
		http.Error(w, "", http.StatusNotFound)
	}

}

func (h *Peers) GetPeers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		accountId := extractAccountIdFromRequestContext(r)
		//new user -> create a new account
		account, err := h.accountManager.GetOrCreateAccount(accountId)
		if err != nil {
			log.Errorf("failed getting user account %s: %v", accountId, err)
			http.Redirect(w, r, "/", http.StatusInternalServerError)
			return
		}

		respBody := []*PeerResponse{}
		for _, peer := range account.Peers {
			respBody = append(respBody, toPeerResponse(peer))
		}
		writeJSONObject(w, respBody)
		return
	default:
		http.Error(w, "", http.StatusNotFound)
	}
}

func toPeerResponse(peer *server.Peer) *PeerResponse {
	return &PeerResponse{
		Name:      peer.Name,
		IP:        peer.IP.String(),
		Connected: peer.Connected,
		LastSeen:  peer.LastSeen,
		OS:        peer.OS,
	}
}
