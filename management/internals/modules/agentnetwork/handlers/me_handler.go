package handlers

import (
	"net/http"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
)

// addMeEndpoints registers the self-service "My Agent Network" route.
// It is available to every authenticated user regardless of role: the
// response is scoped strictly to the caller, which is tighter than any
// role gate could be. The caller's own usage and requests are served by
// the regular usage/logs endpoints, which self-scope for callers without
// the account-wide grants.
func (h *handler) addMeEndpoints(router *mux.Router) {
	router.HandleFunc("/agent-network/agent-config", h.getMySetup).Methods("GET", "OPTIONS")
}

func (h *handler) getMySetup(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	setup, err := h.manager.GetSetupForUser(r.Context(), userAuth.AccountId, userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, setupToAPI(setup))
}

func setupToAPI(setup *types.EffectiveSetup) api.AgentNetworkMeSetup {
	providers := make([]api.AgentNetworkMeProvider, 0, len(setup.Providers))
	for _, p := range setup.Providers {
		providers = append(providers, api.AgentNetworkMeProvider{
			Name:             p.Name,
			CatalogId:        p.CatalogID,
			ApiFlavor:        p.APIFlavor,
			AllModelsAllowed: p.AllModelsAllowed,
			Models:           p.Models,
		})
	}
	return api.AgentNetworkMeSetup{
		Configured: setup.Configured,
		Endpoint:   setup.Endpoint,
		Providers:  providers,
	}
}
