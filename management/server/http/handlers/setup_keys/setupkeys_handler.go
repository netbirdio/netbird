package setup_keys

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/http/configs"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/management/server/types"
)

// handler is a handler that returns a list of setup keys of the account
type handler struct {
	accountManager  server.AccountManager
	claimsExtractor *jwtclaims.ClaimsExtractor
}

func AddEndpoints(accountManager server.AccountManager, authCfg configs.AuthCfg, router *mux.Router) {
	keysHandler := newHandler(accountManager, authCfg)
	router.HandleFunc("/setup-keys", keysHandler.getAllSetupKeys).Methods("GET", "OPTIONS")
	router.HandleFunc("/setup-keys", keysHandler.createSetupKey).Methods("POST", "OPTIONS")
	router.HandleFunc("/setup-keys/{keyId}", keysHandler.getSetupKey).Methods("GET", "OPTIONS")
	router.HandleFunc("/setup-keys/{keyId}", keysHandler.updateSetupKey).Methods("PUT", "OPTIONS")
	router.HandleFunc("/setup-keys/{keyId}", keysHandler.deleteSetupKey).Methods("DELETE", "OPTIONS")
}

// newHandler creates a new setup key handler
func newHandler(accountManager server.AccountManager, authCfg configs.AuthCfg) *handler {
	return &handler{
		accountManager: accountManager,
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithAudience(authCfg.Audience),
			jwtclaims.WithUserIDClaim(authCfg.UserIDClaim),
		),
	}
}

// createSetupKey is a POST requests that creates a new SetupKey
func (h *handler) createSetupKey(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.accountManager.GetAccountIDFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	req := &api.PostApiSetupKeysJSONRequestBody{}
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	if req.Name == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "setup key name shouldn't be empty"), w)
		return
	}

	if !(types.SetupKeyType(req.Type) == types.SetupKeyReusable ||
		types.SetupKeyType(req.Type) == types.SetupKeyOneOff) {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "unknown setup key type %s", req.Type), w)
		return
	}

	expiresIn := time.Duration(req.ExpiresIn) * time.Second

	if expiresIn < 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "expiresIn can not be in the past"), w)
		return
	}

	if req.AutoGroups == nil {
		req.AutoGroups = []string{}
	}

	var ephemeral bool
	if req.Ephemeral != nil {
		ephemeral = *req.Ephemeral
	}

	setupKey, err := h.accountManager.CreateSetupKey(r.Context(), accountID, req.Name, types.SetupKeyType(req.Type), expiresIn,
		req.AutoGroups, req.UsageLimit, userID, ephemeral)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	apiSetupKeys := ToResponseBody(setupKey)
	// for the creation we need to send the plain key
	apiSetupKeys.Key = setupKey.Key

	util.WriteJSONObject(r.Context(), w, apiSetupKeys)
}

// getSetupKey is a GET request to get a SetupKey by ID
func (h *handler) getSetupKey(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.accountManager.GetAccountIDFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	vars := mux.Vars(r)
	keyID := vars["keyId"]
	if len(keyID) == 0 {
		util.WriteError(r.Context(), status.NewInvalidKeyIDError(), w)
		return
	}

	key, err := h.accountManager.GetSetupKey(r.Context(), accountID, userID, keyID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	writeSuccess(r.Context(), w, key)
}

// updateSetupKey is a PUT request to update server.SetupKey
func (h *handler) updateSetupKey(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.accountManager.GetAccountIDFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	vars := mux.Vars(r)
	keyID := vars["keyId"]
	if len(keyID) == 0 {
		util.WriteError(r.Context(), status.NewInvalidKeyIDError(), w)
		return
	}

	req := &api.PutApiSetupKeysKeyIdJSONRequestBody{}
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	if req.AutoGroups == nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "setup key AutoGroups field is invalid"), w)
		return
	}

	newKey := &types.SetupKey{}
	newKey.AutoGroups = req.AutoGroups
	newKey.Revoked = req.Revoked
	newKey.Id = keyID

	newKey, err = h.accountManager.SaveSetupKey(r.Context(), accountID, newKey, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	writeSuccess(r.Context(), w, newKey)
}

// getAllSetupKeys is a GET request that returns a list of SetupKey
func (h *handler) getAllSetupKeys(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.accountManager.GetAccountIDFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	setupKeys, err := h.accountManager.ListSetupKeys(r.Context(), accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	apiSetupKeys := make([]*api.SetupKey, 0)
	for _, key := range setupKeys {
		apiSetupKeys = append(apiSetupKeys, ToResponseBody(key))
	}

	util.WriteJSONObject(r.Context(), w, apiSetupKeys)
}

func (h *handler) deleteSetupKey(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.accountManager.GetAccountIDFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	vars := mux.Vars(r)
	keyID := vars["keyId"]
	if len(keyID) == 0 {
		util.WriteError(r.Context(), status.NewInvalidKeyIDError(), w)
		return
	}

	err = h.accountManager.DeleteSetupKey(r.Context(), accountID, userID, keyID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, util.EmptyObject{})
}

func writeSuccess(ctx context.Context, w http.ResponseWriter, key *types.SetupKey) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	err := json.NewEncoder(w).Encode(ToResponseBody(key))
	if err != nil {
		util.WriteError(ctx, err, w)
		return
	}
}

func ToResponseBody(key *types.SetupKey) *api.SetupKey {
	var state string
	switch {
	case key.IsExpired():
		state = "expired"
	case key.IsRevoked():
		state = "revoked"
	case key.IsOverUsed():
		state = "overused"
	default:
		state = "valid"
	}

	return &api.SetupKey{
		Id:         key.Id,
		Key:        key.KeySecret,
		Name:       key.Name,
		Expires:    key.GetExpiresAt(),
		Type:       string(key.Type),
		Valid:      key.IsValid(),
		Revoked:    key.Revoked,
		UsedTimes:  key.UsedTimes,
		LastUsed:   key.GetLastUsed(),
		State:      state,
		AutoGroups: key.AutoGroups,
		UpdatedAt:  key.UpdatedAt,
		UsageLimit: key.UsageLimit,
		Ephemeral:  key.Ephemeral,
	}
}
