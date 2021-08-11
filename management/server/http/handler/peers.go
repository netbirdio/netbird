package handler

import (
	"encoding/json"
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/management/server"
	"net/http"
)

// Peers is a handler that returns peers of the account
type Peers struct {
	accountManager *server.AccountManager
}

// PeerResponse is a response sent to the client
type PeerResponse struct {
	Key string
	IP  string
}

func NewPeers(accountManager *server.AccountManager) *Peers {
	return &Peers{
		accountManager: accountManager,
	}
}

func (h *Peers) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

		w.WriteHeader(200)
		w.Header().Set("Content-Type", "application/json")

		respBody := []*PeerResponse{}
		for _, peer := range account.Peers {
			respBody = append(respBody, &PeerResponse{
				Key: peer.Key,
				IP:  peer.IP.String(),
			})
		}

		err = json.NewEncoder(w).Encode(respBody)
		if err != nil {
			log.Errorf("failed encoding account peers %s: %v", accountId, err)
			http.Redirect(w, r, "/", http.StatusInternalServerError)
			return
		}
	case http.MethodOptions:
	default:
		http.Error(w, "", http.StatusNotFound)
	}
}
