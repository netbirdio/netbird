package http

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/status"
)

// SetupKeys is a handler that returns a list of setup keys of the account
type SetupKeys struct {
	accountManager  server.AccountManager
	claimsExtractor *jwtclaims.ClaimsExtractor
}

func NewSetupKeysHandler(accountManager server.AccountManager, authCfg AuthCfg) *SetupKeys {
	return &SetupKeys{
		accountManager: accountManager,
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithAudience(authCfg.Audience),
			jwtclaims.WithUserIDClaim(authCfg.UserIDClaim),
		),
	}
}

// CreateSetupKeyHandler is a POST requests that creates a new SetupKey
func (h *SetupKeys) CreateSetupKeyHandler(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	req := &api.PostApiSetupKeysJSONRequestBody{}
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	if req.Name == "" {
		util.WriteError(status.Errorf(status.InvalidArgument, "setup key name shouldn't be empty"), w)
		return
	}

	if !(server.SetupKeyType(req.Type) == server.SetupKeyReusable ||
		server.SetupKeyType(req.Type) == server.SetupKeyOneOff) {
		util.WriteError(status.Errorf(status.InvalidArgument, "unknown setup key type %s", req.Type), w)
		return
	}

	expiresIn := time.Duration(req.ExpiresIn) * time.Second

	if req.AutoGroups == nil {
		req.AutoGroups = []string{}
	}

	setupKey, err := h.accountManager.CreateSetupKey(account.Id, req.Name, server.SetupKeyType(req.Type), expiresIn,
		req.AutoGroups, req.UsageLimit, user.Id)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	writeSuccess(w, setupKey)
}

// GetSetupKeyHandler is a GET request to get a SetupKey by ID
func (h *SetupKeys) GetSetupKeyHandler(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	vars := mux.Vars(r)
	keyID := vars["id"]
	if len(keyID) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid key ID"), w)
		return
	}

	key, err := h.accountManager.GetSetupKey(account.Id, user.Id, keyID)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	writeSuccess(w, key)
}

// UpdateSetupKeyHandler is a PUT request to update server.SetupKey
func (h *SetupKeys) UpdateSetupKeyHandler(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	vars := mux.Vars(r)
	keyID := vars["id"]
	if len(keyID) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid key ID"), w)
		return
	}

	req := &api.PutApiSetupKeysIdJSONRequestBody{}
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	if req.Name == "" {
		util.WriteError(status.Errorf(status.InvalidArgument, "setup key name field is invalid: %s", req.Name), w)
		return
	}

	if req.AutoGroups == nil {
		util.WriteError(status.Errorf(status.InvalidArgument, "setup key AutoGroups field is invalid"), w)
		return
	}

	newKey := &server.SetupKey{}
	newKey.AutoGroups = req.AutoGroups
	newKey.Revoked = req.Revoked
	newKey.Name = req.Name
	newKey.Id = keyID

	newKey, err = h.accountManager.SaveSetupKey(account.Id, newKey, user.Id)
	if err != nil {
		util.WriteError(err, w)
		return
	}
	writeSuccess(w, newKey)
}

// GetAllSetupKeysHandler is a GET request that returns a list of SetupKey
func (h *SetupKeys) GetAllSetupKeysHandler(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	setupKeys, err := h.accountManager.ListSetupKeys(account.Id, user.Id)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	apiSetupKeys := make([]*api.SetupKey, 0)
	for _, key := range setupKeys {
		apiSetupKeys = append(apiSetupKeys, toResponseBody(key))
	}

	util.WriteJSONObject(w, apiSetupKeys)
}

func writeSuccess(w http.ResponseWriter, key *server.SetupKey) {
	w.WriteHeader(200)
	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(toResponseBody(key))
	if err != nil {
		util.WriteError(err, w)
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
		UpdatedAt:  key.UpdatedAt,
		UsageLimit: key.UsageLimit,
	}
}
