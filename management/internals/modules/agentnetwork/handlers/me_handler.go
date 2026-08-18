package handlers

import (
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
)

// addMeEndpoints registers the self-service "My Agent Network" routes.
// Both are available to every authenticated user regardless of role: the
// responses are scoped strictly to the caller, which is tighter than any
// role gate could be.
func (h *handler) addMeEndpoints(router *mux.Router) {
	router.HandleFunc("/agent-network/me/setup", h.getMySetup).Methods("GET", "OPTIONS")
	router.HandleFunc("/agent-network/me/usage/overview", h.getMyUsageOverview).Methods("GET", "OPTIONS")
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

// getMyUsageOverview mirrors the admin usage overview — same filter
// parsing, bounds, granularity, and bucket response — with the identity
// filters overridden to the caller inside the manager, so the dashboard
// renders "My Usage" with the exact component the admin view uses.
func (h *handler) getMyUsageOverview(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	var filter types.AgentNetworkAccessLogFilter
	if err := filter.ParseFromRequest(r); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	filter.ApplyUsageOverviewBounds(time.Now())
	granularity := types.ParseUsageGranularity(r.URL.Query().Get("granularity"))

	buckets, err := h.manager.GetUsageOverviewForUser(r.Context(), userAuth.AccountId, userAuth.UserId, filter, granularity)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	out := make([]api.AgentNetworkUsageBucket, 0, len(buckets))
	for _, b := range buckets {
		out = append(out, b.ToAPIResponse())
	}
	util.WriteJSONObject(r.Context(), w, out)
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
