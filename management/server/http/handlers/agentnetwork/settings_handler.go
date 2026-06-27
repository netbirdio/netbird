package agentnetwork

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

// addSettingsEndpoints registers the Agent Network settings routes. The
// settings row is bootstrapped server-side on first provider create; GET reads
// it and PUT updates the mutable collection toggles (cluster/subdomain stay
// immutable).
func (h *handler) addSettingsEndpoints(router *mux.Router) {
	router.HandleFunc("/agent-network/settings", h.getSettings).Methods("GET", "OPTIONS")
	router.HandleFunc("/agent-network/settings", h.updateSettings).Methods("PUT", "OPTIONS")
}

// updateSettings applies the collection toggles to the account's settings row.
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

// getSettings returns the account's agent-network settings. The settings
// row is bootstrapped on first provider create, so freshly-onboarded
// accounts have nothing to read. Rather than 404-ing in that case (which
// the dashboard would have to special-case), return a JSON null with 200
// so consumers can branch on the body alone.
func (h *handler) getSettings(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	settings, err := h.manager.GetSettings(r.Context(), userAuth.AccountId, userAuth.UserId)
	if err != nil {
		var sErr *status.Error
		if errors.As(err, &sErr) && sErr.Type() == status.NotFound {
			util.WriteJSONObject(r.Context(), w, nil)
			return
		}
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, settings.ToAPIResponse())
}
