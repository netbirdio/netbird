// Package handlers serves the Agent Network HTTP API.
//
// All persistence is delegated to agentnetwork.Manager so this layer only
// translates between the wire format (api.AgentNetworkProvider*) and the
// domain types.
package handlers

import (
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork"
	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/catalog"
	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/modeldiscovery"
	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/pricing"
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
	router.HandleFunc("/agent-network/catalog/providers/models", h.discoverProviderModels).Methods("POST", "OPTIONS")
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
	h.addAgentConfigEndpoints(router)
}

func (h *handler) getCatalogProviders(w http.ResponseWriter, r *http.Request) {
	if _, err := nbcontext.GetUserAuthFromContext(r.Context()); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	entries := catalog.All()
	out := make([]api.AgentNetworkCatalogProvider, 0, len(entries))
	for _, e := range entries {
		resp := e.ToAPIResponse()
		applyDefaultPricing(e, &resp)
		out = append(out, resp)
	}
	util.WriteJSONObject(r.Context(), w, out)
}

// discoverProviderModels asks the vendor which models the operator's own
// credential can reach, so the provider form can offer a live list rather than
// only the static catalog.
func (h *handler) discoverProviderModels(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	var body api.AgentNetworkModelDiscoveryRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		util.WriteErrorResponse("invalid json", http.StatusBadRequest, w)
		return
	}
	// Trimmed once and carried, not trimmed for the emptiness test and then
	// discarded: a padded " openai_api " would clear the check here and miss
	// the catalog lookup, reporting the provider as unknown.
	catalogID := strings.TrimSpace(body.CatalogProviderId)
	if catalogID == "" {
		util.WriteErrorResponse("catalog_provider_id is required", http.StatusBadRequest, w)
		return
	}

	recordID := strValue(body.ProviderId)
	req := modeldiscovery.Request{
		CatalogID:   catalogID,
		UpstreamURL: strValue(body.UpstreamUrl),
		APIKey:      strValue(body.ApiKey),
	}
	// One source of credential or the other, never a mix: taking a key from
	// the request while addressing a saved record would let a caller run an
	// arbitrary credential against a provider they can only read.
	if recordID != "" && req.APIKey != "" {
		util.WriteErrorResponse("provide either provider_id or api_key, not both", http.StatusBadRequest, w)
		return
	}

	models, err := h.manager.DiscoverProviderModels(r.Context(), userAuth.AccountId, userAuth.UserId, req, recordID)
	if err != nil {
		// A provider with no listing endpoint is a fact about the catalog
		// entry, not a failure: the caller falls back to the catalog's own
		// models, so it must be able to tell the two apart.
		if errors.Is(err, modeldiscovery.ErrNoDiscovery) {
			util.WriteErrorResponse(err.Error(), http.StatusUnprocessableEntity, w)
			return
		}
		// An unknown provider, an unusable upstream, a missing region or a
		// missing key are all things the caller sent, reachable from a
		// well-formed request. Reporting them as 500 tells the operator the
		// server broke and buries genuine faults in the error rate.
		if errors.Is(err, modeldiscovery.ErrInvalidRequest) {
			util.WriteErrorResponse(err.Error(), http.StatusBadRequest, w)
			return
		}
		util.WriteError(r.Context(), err, w)
		return
	}

	out := api.AgentNetworkModelDiscoveryResponse{Models: make([]api.AgentNetworkDiscoveredModel, 0, len(models))}
	for _, m := range models {
		entry := api.AgentNetworkDiscoveredModel{
			Id:           m.ID,
			PricingKnown: m.PricingKnown,
			// Sent even when zero: the form prefills every discovered model as
			// an editable row, and an unpriced one is shown at zero and flagged
			// rather than left out.
			InputPer1k:  m.InputPer1k,
			OutputPer1k: m.OutputPer1k,
			// Cache rates stay absent when unset, matching the catalog
			// response — a zero would read as "free", not "not applicable".
			CachedInputPer1k:   positiveRatePtr(m.CachedInputPer1k),
			CacheReadPer1k:     positiveRatePtr(m.CacheReadPer1k),
			CacheCreationPer1k: positiveRatePtr(m.CacheCreationPer1k),
		}
		if m.Label != "" {
			label := m.Label
			entry.Label = &label
		}
		out.Models = append(out.Models, entry)
	}
	util.WriteJSONObject(r.Context(), w, out)
}

// strValue reads an optional string field, treating absent as empty.
func strValue(v *string) string {
	if v == nil {
		return ""
	}
	return strings.TrimSpace(*v)
}

// applyDefaultPricing overwrites the catalog response's model rates with
// the LIVE default pricing table, which may differ from the compiled-in
// catalog rates when the operator provides a defaults_llm_pricing.yaml.
// This keeps the dashboard's model-row prefill identical to what the
// proxy will actually bill — the same table the synthesizer ships.
func applyDefaultPricing(cp catalog.Provider, resp *api.AgentNetworkCatalogProvider) {
	if len(cp.PricingSurfaces) == 0 {
		return
	}
	for i := range resp.Models {
		m := &resp.Models[i]
		e, ok := pricing.LookupDefault(cp.PricingSurfaces, m.Id)
		if !ok {
			continue
		}
		m.InputPer1k = e.InputPer1k
		m.OutputPer1k = e.OutputPer1k
		m.CachedInputPer1k = positiveRatePtr(e.CachedInputPer1k)
		m.CacheReadPer1k = positiveRatePtr(e.CacheReadPer1k)
		m.CacheCreationPer1k = positiveRatePtr(e.CacheCreationPer1k)
	}
}

// positiveRatePtr renders a cache rate for the API: absent (nil) when
// unset, matching the catalog response convention.
func positiveRatePtr(v float64) *float64 {
	if v <= 0 {
		return nil
	}
	return &v
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

	created, err := h.manager.CreateProvider(r.Context(), userAuth.UserId, provider)
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
	// An update omits api_key to keep the stored credential. A key that is
	// present but blank is not that: Provider.FromAPIRequest drops it exactly
	// as if it were absent, so a rotation the operator believes they performed
	// would answer 200 having changed nothing. Refuse it here, where the
	// request still carries the difference between absent and blank.
	if req.ApiKey != nil && strings.TrimSpace(*req.ApiKey) == "" {
		return status.Errorf(status.InvalidArgument, "api_key must be omitted to keep the stored credential rather than sent blank")
	}
	if req.Models != nil {
		for i, m := range *req.Models {
			if err := validateModel(i, m); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateModel is the single ingress guard for operator-entered pricing:
// these rates are synthesized into the proxy's cost_meter config verbatim,
// and a negative or non-finite rate there would poison every cost the
// proxy records, so reject at the API boundary.
func validateModel(i int, m api.AgentNetworkProviderModel) error {
	if strings.TrimSpace(m.Id) == "" {
		return status.Errorf(status.InvalidArgument, "models[%d]: id is required", i)
	}
	rates := map[string]*float64{
		"input_per_1k":          &m.InputPer1k,
		"output_per_1k":         &m.OutputPer1k,
		"cached_input_per_1k":   m.CachedInputPer1k,
		"cache_read_per_1k":     m.CacheReadPer1k,
		"cache_creation_per_1k": m.CacheCreationPer1k,
	}
	for field, v := range rates {
		if v == nil {
			continue
		}
		if *v < 0 || math.IsNaN(*v) || math.IsInf(*v, 0) {
			return status.Errorf(status.InvalidArgument, "models[%d] (%s): %s must be a finite, non-negative USD rate", i, m.Id, field)
		}
	}
	return nil
}
