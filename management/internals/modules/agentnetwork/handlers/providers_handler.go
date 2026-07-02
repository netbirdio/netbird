// Package handlers serves the Agent Network HTTP API.
//
// All persistence is delegated to agentnetwork.Manager so this layer only
// translates between the wire format (api.AgentNetworkProvider*) and the
// domain types.
package handlers

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork"
	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/catalog"
	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

type handler struct {
	manager agentnetwork.Manager
}

// RegisterEndpoints registers all Agent Network routes.
func RegisterEndpoints(manager agentnetwork.Manager, router *mux.Router) {
	h := &handler{manager: manager}
	router.HandleFunc("/agent-network/catalog/providers", h.getCatalogProviders).Methods("GET", "OPTIONS")
	router.HandleFunc("/agent-network/providers", h.getAllProviders).Methods("GET", "OPTIONS")
	router.HandleFunc("/agent-network/providers", h.createProvider).Methods("POST", "OPTIONS")
	router.HandleFunc("/agent-network/providers/{providerId}", h.getProvider).Methods("GET", "OPTIONS")
	router.HandleFunc("/agent-network/providers/{providerId}", h.updateProvider).Methods("PUT", "OPTIONS")
	router.HandleFunc("/agent-network/providers/{providerId}", h.deleteProvider).Methods("DELETE", "OPTIONS")
	h.addPolicyEndpoints(router)
	h.addGuardrailEndpoints(router)
	h.addSettingsEndpoints(router)
	h.addConsumptionEndpoints(router)
	h.addAccessLogEndpoints(router)
	h.addBudgetRuleEndpoints(router)
}

func (h *handler) getCatalogProviders(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	entries := catalog.All()
	out := make([]api.AgentNetworkCatalogProvider, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.ToAPIResponse())
	}
	util.WriteJSONObject(r.Context(), w, out)
}

func (h *handler) getAllProviders(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	providers, err := h.manager.GetAllProviders(r.Context(), userAuth.AccountId, userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	out := make([]*api.AgentNetworkProvider, 0, len(providers))
	for _, p := range providers {
		out = append(out, p.ToAPIResponse())
	}
	util.WriteJSONObject(r.Context(), w, out)
}

func (h *handler) getProvider(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	providerID := mux.Vars(r)["providerId"]
	if providerID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "provider ID is required"), w)
		return
	}

	provider, err := h.manager.GetProvider(r.Context(), userAuth.AccountId, userAuth.UserId, providerID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, provider.ToAPIResponse())
}

func (h *handler) createProvider(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	var req api.AgentNetworkProviderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	if err := validate(&req, true); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	provider := types.NewProvider(userAuth.AccountId)
	provider.FromAPIRequest(&req)

	bootstrapCluster := ""
	if req.BootstrapCluster != nil {
		bootstrapCluster = *req.BootstrapCluster
	}

	created, err := h.manager.CreateProvider(r.Context(), userAuth.UserId, provider, bootstrapCluster)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, created.ToAPIResponse())
}

func (h *handler) updateProvider(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	providerID := mux.Vars(r)["providerId"]
	if providerID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "provider ID is required"), w)
		return
	}

	var req api.AgentNetworkProviderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	if err := validate(&req, false); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	provider := &types.Provider{
		ID:        providerID,
		AccountID: userAuth.AccountId,
	}
	provider.FromAPIRequest(&req)

	updated, err := h.manager.UpdateProvider(r.Context(), userAuth.UserId, provider)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, updated.ToAPIResponse())
}

func (h *handler) deleteProvider(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	providerID := mux.Vars(r)["providerId"]
	if providerID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "provider ID is required"), w)
		return
	}

	if err := h.manager.DeleteProvider(r.Context(), userAuth.AccountId, userAuth.UserId, providerID); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, util.EmptyObject{})
}

func validate(req *api.AgentNetworkProviderRequest, requireAPIKey bool) error {
	if strings.TrimSpace(req.ProviderId) == "" {
		return status.Errorf(status.InvalidArgument, "provider_id is required")
	}
	if !catalog.IsKnown(req.ProviderId) {
		return status.Errorf(status.InvalidArgument, "provider_id %q is not a known catalog provider", req.ProviderId)
	}
	if strings.TrimSpace(req.Name) == "" {
		return status.Errorf(status.InvalidArgument, "name is required")
	}
	if strings.TrimSpace(req.UpstreamUrl) == "" {
		return status.Errorf(status.InvalidArgument, "upstream_url is required")
	}
	u, err := url.Parse(strings.TrimSpace(req.UpstreamUrl))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return status.Errorf(status.InvalidArgument, "upstream_url must be a full http(s) URL")
	}
	if requireAPIKey && (req.ApiKey == nil || strings.TrimSpace(*req.ApiKey) == "") {
		return status.Errorf(status.InvalidArgument, "api_key is required")
	}
	return nil
}
