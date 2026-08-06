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

// addSettingsEndpoints registers the Agent Network settings routes. POST
// bootstraps the settings row, assigning the account's immutable endpoint;
// GET reads it (defaults with an empty endpoint before bootstrap) and PUT
// replaces the mutable collection toggles. The identity fields are not part
// of the PUT schema — immutability by shape, not by rejection.
func (h *handler) addSettingsEndpoints(router *mux.Router) {
	router.HandleFunc("/agent-network/settings", h.getSettings).Methods("GET", "OPTIONS")
	router.HandleFunc("/agent-network/settings", h.createSettings).Methods("POST", "OPTIONS")
	router.HandleFunc("/agent-network/settings", h.updateSettings).Methods("PUT", "OPTIONS")
}

// createSettings bootstraps the account's settings row. Exactly one of
// proxy_address (labeled endpoint; the server allocates the label) and
// endpoint (self-addressed, claimed verbatim) must be provided; optional
// collection toggles ride along with defaults for omitted fields.
func (h *handler) createSettings(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	var req api.AgentNetworkSettingsCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	settings := types.DefaultSettings(userAuth.AccountId)
	settings.FromAPICreateRequest(&req)

	proxyAddress := ""
	if req.ProxyAddress != nil {
		proxyAddress = *req.ProxyAddress
	}
	endpoint := ""
	if req.Endpoint != nil {
		endpoint = *req.Endpoint
	}

	created, err := h.manager.CreateSettings(r.Context(), userAuth.UserId, settings, proxyAddress, endpoint)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, created.ToAPIResponse())
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

// getSettings returns the account's agent-network settings. Accounts that
// haven't been bootstrapped yet read as the defaults with an empty cluster,
// subdomain and endpoint; the manager synthesises that view.
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
