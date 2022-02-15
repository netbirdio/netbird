package handler

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/management/server"
	"github.com/wiretrustee/wiretrustee/util"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"net/http"
	"time"
)

// SetupKeys is a handler that returns a list of setup keys of the account
type SetupKeys struct {
	accountManager *server.DefaultAccountManager
	authAudience   string
}

// SetupKeyResponse is a response sent to the client
type SetupKeyResponse struct {
	Id        string
	Key       string
	Name      string
	Expires   time.Time
	Type      server.SetupKeyType
	Valid     bool
	Revoked   bool
	UsedTimes int
	LastUsed  time.Time
	State     string
}

// SetupKeyRequest is a request sent by client. This object contains fields that can be modified
type SetupKeyRequest struct {
	Name      string
	Type      server.SetupKeyType
	ExpiresIn *util.Duration
	Revoked   bool
}

func NewSetupKeysHandler(accountManager *server.DefaultAccountManager, authAudience string) *SetupKeys {
	return &SetupKeys{
		accountManager: accountManager,
		authAudience:   authAudience,
	}
}

func (h *SetupKeys) updateKey(accountId string, keyId string, w http.ResponseWriter, r *http.Request) {
	req := &SetupKeyRequest{}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var key *server.SetupKey
	if req.Revoked {
		//handle only if being revoked, don't allow to enable key again for now
		key, err = h.accountManager.RevokeSetupKey(accountId, keyId)
		if err != nil {
			http.Error(w, "failed revoking key", http.StatusInternalServerError)
			return
		}
	}
	if len(req.Name) != 0 {
		key, err = h.accountManager.RenameSetupKey(accountId, keyId, req.Name)
		if err != nil {
			http.Error(w, "failed renaming key", http.StatusInternalServerError)
			return
		}
	}

	if key != nil {
		writeSuccess(w, key)
	}
}

func (h *SetupKeys) getKey(accountId string, keyId string, w http.ResponseWriter, r *http.Request) {
	account, err := h.accountManager.GetAccountById(accountId)
	if err != nil {
		http.Error(w, "account doesn't exist", http.StatusInternalServerError)
		return
	}
	for _, key := range account.SetupKeys {
		if key.Id == keyId {
			writeSuccess(w, key)
			return
		}
	}
	http.Error(w, "setup key not found", http.StatusNotFound)
}

func (h *SetupKeys) createKey(accountId string, w http.ResponseWriter, r *http.Request) {
	req := &SetupKeyRequest{}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if !(req.Type == server.SetupKeyReusable || req.Type == server.SetupKeyOneOff) {
		http.Error(w, "unknown setup key type "+string(req.Type), http.StatusBadRequest)
		return
	}

	setupKey, err := h.accountManager.AddSetupKey(accountId, req.Name, req.Type, req.ExpiresIn)
	if err != nil {
		errStatus, ok := status.FromError(err)
		if ok && errStatus.Code() == codes.NotFound {
			http.Error(w, "account not found", http.StatusNotFound)
			return
		}
		http.Error(w, "failed adding setup key", http.StatusInternalServerError)
		return
	}

	writeSuccess(w, setupKey)
}

func (h *SetupKeys) getSetupKeyAccount(r *http.Request) (*server.Account, error) {
	jwtClaims := extractClaimsFromRequestContext(r, h.authAudience)

	account, err := h.accountManager.GetAccountByUserOrAccountId(jwtClaims.UserId, jwtClaims.AccountId, jwtClaims.Domain)
	if err != nil {
		return nil, fmt.Errorf("failed getting account of a user %s: %v", jwtClaims.UserId, err)
	}

	return account, nil
}

func (h *SetupKeys) HandleKey(w http.ResponseWriter, r *http.Request) {
	account, err := h.getSetupKeyAccount(r)
	if err != nil {
		log.Error(err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	vars := mux.Vars(r)
	keyId := vars["id"]
	if len(keyId) == 0 {
		http.Error(w, "invalid key Id", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodPut:
		h.updateKey(account.Id, keyId, w, r)
		return
	case http.MethodGet:
		h.getKey(account.Id, keyId, w, r)
		return
	default:
		http.Error(w, "", http.StatusNotFound)
	}
}

func (h *SetupKeys) GetKeys(w http.ResponseWriter, r *http.Request) {

	account, err := h.getSetupKeyAccount(r)
	if err != nil {
		log.Error(err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	switch r.Method {
	case http.MethodPost:
		h.createKey(account.Id, w, r)
		return
	case http.MethodGet:
		w.WriteHeader(200)
		w.Header().Set("Content-Type", "application/json")

		respBody := []*SetupKeyResponse{}
		for _, key := range account.SetupKeys {
			respBody = append(respBody, toResponseBody(key))
		}

		err = json.NewEncoder(w).Encode(respBody)
		if err != nil {
			log.Errorf("failed encoding account peers %s: %v", account.Id, err)
			http.Redirect(w, r, "/", http.StatusInternalServerError)
			return
		}
	default:
		http.Error(w, "", http.StatusNotFound)
	}
}

func writeSuccess(w http.ResponseWriter, key *server.SetupKey) {
	w.WriteHeader(200)
	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(toResponseBody(key))
	if err != nil {
		http.Error(w, "failed handling request", http.StatusInternalServerError)
		return
	}
}

func toResponseBody(key *server.SetupKey) *SetupKeyResponse {
	var state string
	if key.IsExpired() {
		state = "expired"
	} else if key.IsRevoked() {
		state = "revoked"
	} else if key.IsOverUsed() {
		state = "overused"
	} else {
		state = "valid"
	}
	return &SetupKeyResponse{
		Id:        key.Id,
		Key:       key.Key,
		Name:      key.Name,
		Expires:   key.ExpiresAt,
		Type:      key.Type,
		Valid:     key.IsValid(),
		Revoked:   key.Revoked,
		UsedTimes: key.UsedTimes,
		LastUsed:  key.LastUsed,
		State:     state,
	}
}
