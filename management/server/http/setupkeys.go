package http

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"net/http"
	"time"
)

// SetupKeys is a handler that returns a list of setup keys of the account
type SetupKeys struct {
	accountManager server.AccountManager
	jwtExtractor   jwtclaims.ClaimsExtractor
	authAudience   string
}

func NewSetupKeysHandler(accountManager server.AccountManager, authAudience string) *SetupKeys {
	return &SetupKeys{
		accountManager: accountManager,
		authAudience:   authAudience,
		jwtExtractor:   *jwtclaims.NewClaimsExtractor(nil),
	}
}

// CreateSetupKeyHandler is a POST requests that creates a new SetupKey
func (h *SetupKeys) CreateSetupKeyHandler(w http.ResponseWriter, r *http.Request) {
	account, err := getJWTAccount(h.accountManager, h.jwtExtractor, h.authAudience, r)
	if err != nil {
		log.Error(err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	req := &api.PostApiSetupKeysJSONRequestBody{}
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		http.Error(w, "Setup key name shouldn't be empty", http.StatusUnprocessableEntity)
		return
	}

	if !(server.SetupKeyType(req.Type) == server.SetupKeyReusable ||
		server.SetupKeyType(req.Type) == server.SetupKeyOneOff) {

		http.Error(w, "unknown setup key type "+string(req.Type), http.StatusBadRequest)
		return
	}

	expiresIn := time.Duration(req.ExpiresIn) * time.Second

	if req.AutoGroups == nil {
		req.AutoGroups = []string{}
	}
	// newExpiresIn := time.Duration(req.ExpiresIn) * time.Second
	// newKey.ExpiresAt = time.Now().Add(newExpiresIn)
	setupKey, err := h.accountManager.CreateSetupKey(account.Id, req.Name, server.SetupKeyType(req.Type), expiresIn,
		req.AutoGroups)
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

// GetSetupKeyHandler is a GET request to get a SetupKey by ID
func (h *SetupKeys) GetSetupKeyHandler(w http.ResponseWriter, r *http.Request) {
	account, err := getJWTAccount(h.accountManager, h.jwtExtractor, h.authAudience, r)
	if err != nil {
		log.Error(err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	vars := mux.Vars(r)
	keyID := vars["id"]
	if len(keyID) == 0 {
		http.Error(w, "invalid key Id", http.StatusBadRequest)
		return
	}

	key, err := h.accountManager.GetSetupKey(account.Id, keyID)
	if err != nil {
		errStatus, ok := status.FromError(err)
		if ok && errStatus.Code() == codes.NotFound {
			http.Error(w, fmt.Sprintf("setup key %s not found under account %s", keyID, account.Id), http.StatusNotFound)
			return
		}
		log.Errorf("failed getting setup key %s under account %s %v", keyID, account.Id, err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	writeSuccess(w, key)
}

// UpdateSetupKeyHandler is a PUT request to update server.SetupKey
func (h *SetupKeys) UpdateSetupKeyHandler(w http.ResponseWriter, r *http.Request) {
	account, err := getJWTAccount(h.accountManager, h.jwtExtractor, h.authAudience, r)
	if err != nil {
		log.Error(err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	vars := mux.Vars(r)
	keyID := vars["id"]
	if len(keyID) == 0 {
		http.Error(w, "invalid key Id", http.StatusBadRequest)
		return
	}

	req := &api.PutApiSetupKeysIdJSONRequestBody{}
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		http.Error(w, fmt.Sprintf("setup key name field is invalid: %s", req.Name), http.StatusBadRequest)
		return
	}

	if req.AutoGroups == nil {
		http.Error(w, fmt.Sprintf("setup key AutoGroups field is invalid: %s", req.AutoGroups), http.StatusBadRequest)
		return
	}

	newKey := &server.SetupKey{}
	newKey.AutoGroups = req.AutoGroups
	newKey.Revoked = req.Revoked
	newKey.Name = req.Name
	newKey.Id = keyID

	newKey, err = h.accountManager.SaveSetupKey(account.Id, newKey)
	if err != nil {
		if err != nil {
			if e, ok := status.FromError(err); ok {
				switch e.Code() {
				case codes.NotFound:
					http.Error(w, fmt.Sprintf("couldn't find setup key for ID %s", keyID), http.StatusNotFound)
				default:
					http.Error(w, "failed updating setup key", http.StatusInternalServerError)
					return
				}
			}
		}
		return
	}
	writeSuccess(w, newKey)
}

// GetAllSetupKeysHandler is a GET request that returns a list of SetupKey
func (h *SetupKeys) GetAllSetupKeysHandler(w http.ResponseWriter, r *http.Request) {

	account, err := getJWTAccount(h.accountManager, h.jwtExtractor, h.authAudience, r)
	if err != nil {
		log.Error(err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(200)
	w.Header().Set("Content-Type", "application/json")

	// should be initialized like that, otherwise json marshaller will return null
	respBody := []*api.SetupKey{}
	for _, key := range account.SetupKeys {
		respBody = append(respBody, toResponseBody(key))
	}

	err = json.NewEncoder(w).Encode(respBody)
	if err != nil {
		log.Errorf("failed encoding account peers %s: %v", account.Id, err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
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

func toResponseBody(key *server.SetupKey) *api.SetupKey {
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

	// the UpdatedAt field was introduced later, so there might be that some keys have a Zero value (e.g, null in the store file)
	var updatedAt time.Time
	if key.UpdatedAt.IsZero() {
		updatedAt = key.CreatedAt
	} else {
		updatedAt = key.UpdatedAt
	}

	return &api.SetupKey{
		Id:         key.Id,
		Key:        key.Key,
		Name:       key.Name,
		Expires:    key.ExpiresAt,
		Type:       string(key.Type),
		Valid:      key.IsValid(),
		Revoked:    key.Revoked,
		UsedTimes:  key.UsedTimes,
		LastUsed:   key.LastUsed,
		State:      state,
		AutoGroups: key.AutoGroups,
		UpdatedAt:  updatedAt,
	}
}
