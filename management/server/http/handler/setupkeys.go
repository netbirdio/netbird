package handler

import (
	"encoding/json"
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/management/server"
	"net/http"
)

// SetupKeys is a handler that returns a list of setup keys of the account
type SetupKeys struct {
	accountManager *server.AccountManager
}

// SetupKeyResponse is a response sent to the client
type SetupKeyResponse struct {
	Key string
}

func NewSetupKeysHandler(accountManager *server.AccountManager) *SetupKeys {
	return &SetupKeys{
		accountManager: accountManager,
	}
}

func (h *SetupKeys) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

		respBody := []*SetupKeyResponse{}
		for _, key := range account.SetupKeys {
			respBody = append(respBody, &SetupKeyResponse{
				Key: key.Key,
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
