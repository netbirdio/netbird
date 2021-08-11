package handler

import (
	"encoding/json"
	"github.com/golang-jwt/jwt"
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
		// since we are here it means that JWT validation was successful in the middleware
		// therefore we can get parsed user token from the request context
		token := r.Context().Value("user").(*jwt.Token)
		claims := token.Claims.(jwt.MapClaims)

		//actually a user id but for now we have a 1 to 1 mapping.
		accountId := claims["sub"].(string)
		//new user -> create a new account
		account, err := h.accountManager.GetOrCreateAccount(accountId)
		if err != nil {
			log.Errorf("failed getting user account %s: %v", accountId, err)
			http.Redirect(w, r, "/", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(200)
		w.Header().Set("Content-Type", "application/json")

		var respBody []*PeerResponse
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
