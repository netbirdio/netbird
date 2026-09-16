package handlers

import (
	"net/http"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
)

// addAgentConfigEndpoints registers the self-service agent-config route.
// It is available to every authenticated user regardless of role: the
// providers in the response are scoped strictly to the caller, which is
// tighter than any role gate could be. The caller's own usage and requests are served by
// the regular usage/logs endpoints, which self-scope for callers without
// the account-wide grants.
func (h *handler) addAgentConfigEndpoints(router *mux.Router) {
	router.HandleFunc("/agent-network/agent-config", h.getAgentConfig).Methods("GET", "OPTIONS")
}

func (h *handler) getAgentConfig(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	setup, err := h.manager.GetAgentConfigForUser(r.Context(), userAuth.AccountId, userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, agentConfigToAPI(setup))
}

func agentConfigToAPI(setup *types.AgentConfig) api.AgentNetworkAgentConfig {
	providers := make([]api.AgentNetworkAgentConfigProvider, 0, len(setup.Providers))
	for _, p := range setup.Providers {
		providers = append(providers, api.AgentNetworkAgentConfigProvider{
			Name:             p.Name,
			CatalogId:        p.CatalogID,
			ApiFlavor:        p.APIFlavor,
			AllModelsAllowed: p.AllModelsAllowed,
			Models:           p.Models,
		})
	}
	return api.AgentNetworkAgentConfig{
		Configured: setup.Configured,
		Endpoint:   setup.Endpoint,
		Providers:  providers,
	}
}
