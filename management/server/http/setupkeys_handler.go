package http

import (
	"context"
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

// SetupKeysHandler is a handler that returns a list of setup keys of the account
type SetupKeysHandler struct {
	accountManager  server.AccountManager
	claimsExtractor *jwtclaims.ClaimsExtractor
}

// NewSetupKeysHandler creates a new SetupKeysHandler HTTP handler
func NewSetupKeysHandler(accountManager server.AccountManager, authCfg AuthCfg) *SetupKeysHandler {
	return &SetupKeysHandler{
		accountManager: accountManager,
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithAudience(authCfg.Audience),
			jwtclaims.WithUserIDClaim(authCfg.UserIDClaim),
		),
	}
}

// CreateSetupKey is a POST requests that creates a new SetupKey
func (h *SetupKeysHandler) CreateSetupKey(w http.ResponseWriter, r *http.Request) {
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

	if !(server.SetupKeyType(req.Type) == server.SetupKeyReusable ||
		server.SetupKeyType(req.Type) == server.SetupKeyOneOff) {
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

	setupKey, err := h.accountManager.CreateSetupKey(r.Context(), accountID, req.Name, server.SetupKeyType(req.Type), expiresIn,
		req.AutoGroups, req.UsageLimit, userID, ephemeral)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	apiSetupKeys := toResponseBody(setupKey)
	// for the creation we need to send the plain key
	apiSetupKeys.Key = setupKey.Key

	util.WriteJSONObject(r.Context(), w, apiSetupKeys)
}

// GetSetupKey is a GET request to get a SetupKey by ID
func (h *SetupKeysHandler) GetSetupKey(w http.ResponseWriter, r *http.Request) {
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

// UpdateSetupKey is a PUT request to update server.SetupKey
func (h *SetupKeysHandler) UpdateSetupKey(w http.ResponseWriter, r *http.Request) {
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

	newKey := &server.SetupKey{}
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

// GetAllSetupKeys is a GET request that returns a list of SetupKey
func (h *SetupKeysHandler) GetAllSetupKeys(w http.ResponseWriter, r *http.Request) {
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
		apiSetupKeys = append(apiSetupKeys, toResponseBody(key))
	}

	util.WriteJSONObject(r.Context(), w, apiSetupKeys)
}

func (h *SetupKeysHandler) DeleteSetupKey(w http.ResponseWriter, r *http.Request) {
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

	util.WriteJSONObject(r.Context(), w, emptyObject{})
}

func writeSuccess(ctx context.Context, w http.ResponseWriter, key *server.SetupKey) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	err := json.NewEncoder(w).Encode(toResponseBody(key))
	if err != nil {
		util.WriteError(ctx, err, w)
		return
	}
}

func toResponseBody(key *server.SetupKey) *api.SetupKey {
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
		Ephemeral:  key.Ephemeral,
	}
}
