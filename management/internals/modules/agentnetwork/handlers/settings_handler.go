package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
)

// addSettingsEndpoints registers the Agent Network settings routes. The
// settings row is bootstrapped server-side on first provider create or on the
// first PUT carrying a cluster; GET reads it and PUT applies a partial update
// of the mutable collection toggles (cluster/subdomain stay immutable).
func (h *handler) addSettingsEndpoints(router *mux.Router) {
	router.HandleFunc("/agent-network/settings", h.getSettings).Methods("GET", "OPTIONS")
	router.HandleFunc("/agent-network/settings", h.updateSettings).Methods("PUT", "OPTIONS")
}

// updateSettings replaces the mutable settings fields on the account's row.
// A request carrying a cluster bootstraps the row when the account doesn't
// have one yet.
func (h *handler) updateSettings(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	var req api.AgentNetworkSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	settings := &types.Settings{AccountID: userAuth.AccountId}
	settings.FromAPIRequest(&req)

	updated, err := h.manager.UpdateSettings(r.Context(), userAuth.UserId, settings)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, updated.ToAPIResponse())
}

// getSettings returns the account's agent-network settings. Freshly-onboarded
// accounts have no settings row until a provider create (or a settings PUT
// with a cluster) bootstraps one; per the OpenAPI contract that reads as a
// plain 404.
func (h *handler) getSettings(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	settings, err := h.manager.GetSettings(r.Context(), userAuth.AccountId, userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, settings.ToAPIResponse())
}
