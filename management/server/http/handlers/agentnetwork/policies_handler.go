package agentnetwork

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/server/agentnetwork/types"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

// minWindowSeconds is the floor enforced on enabled token / budget
// limit windows. One minute is short enough for fine-grained burst
// control without producing untenable consumption-row volume at scale.
const minWindowSeconds int64 = 60

// addPolicyEndpoints registers all Agent Network policy routes on the
// shared handler.
func (h *handler) addPolicyEndpoints(router *mux.Router) {
	router.HandleFunc("/agent-network/policies", h.getAllPolicies).Methods("GET", "OPTIONS")
	router.HandleFunc("/agent-network/policies", h.createPolicy).Methods("POST", "OPTIONS")
	router.HandleFunc("/agent-network/policies/{policyId}", h.getPolicy).Methods("GET", "OPTIONS")
	router.HandleFunc("/agent-network/policies/{policyId}", h.updatePolicy).Methods("PUT", "OPTIONS")
	router.HandleFunc("/agent-network/policies/{policyId}", h.deletePolicy).Methods("DELETE", "OPTIONS")
}

func (h *handler) getAllPolicies(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	policies, err := h.manager.GetAllPolicies(r.Context(), userAuth.AccountId, userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	out := make([]*api.AgentNetworkPolicy, 0, len(policies))
	for _, p := range policies {
		out = append(out, p.ToAPIResponse())
	}
	util.WriteJSONObject(r.Context(), w, out)
}

func (h *handler) getPolicy(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	policyID := mux.Vars(r)["policyId"]
	if policyID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "policy ID is required"), w)
		return
	}

	policy, err := h.manager.GetPolicy(r.Context(), userAuth.AccountId, userAuth.UserId, policyID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, policy.ToAPIResponse())
}

func (h *handler) createPolicy(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	var req api.AgentNetworkPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	if err := validatePolicy(&req); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	policy := types.NewPolicy(userAuth.AccountId)
	policy.FromAPIRequest(&req)

	created, err := h.manager.CreatePolicy(r.Context(), userAuth.UserId, policy)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, created.ToAPIResponse())
}

func (h *handler) updatePolicy(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	policyID := mux.Vars(r)["policyId"]
	if policyID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "policy ID is required"), w)
		return
	}

	var req api.AgentNetworkPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	if err := validatePolicy(&req); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	policy := &types.Policy{
		ID:        policyID,
		AccountID: userAuth.AccountId,
	}
	policy.FromAPIRequest(&req)

	updated, err := h.manager.UpdatePolicy(r.Context(), userAuth.UserId, policy)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, updated.ToAPIResponse())
}

func (h *handler) deletePolicy(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	policyID := mux.Vars(r)["policyId"]
	if policyID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "policy ID is required"), w)
		return
	}

	if err := h.manager.DeletePolicy(r.Context(), userAuth.AccountId, userAuth.UserId, policyID); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, util.EmptyObject{})
}

func validatePolicy(req *api.AgentNetworkPolicyRequest) error {
	if strings.TrimSpace(req.Name) == "" {
		return status.Errorf(status.InvalidArgument, "name is required")
	}
	if len(req.SourceGroups) == 0 {
		return status.Errorf(status.InvalidArgument, "source_groups must contain at least one group id")
	}
	for _, id := range req.SourceGroups {
		if strings.TrimSpace(id) == "" {
			return status.Errorf(status.InvalidArgument, "source_groups must not contain empty entries")
		}
	}
	if len(req.DestinationProviderIds) == 0 {
		return status.Errorf(status.InvalidArgument, "destination_provider_ids must contain at least one provider id")
	}
	for _, id := range req.DestinationProviderIds {
		if strings.TrimSpace(id) == "" {
			return status.Errorf(status.InvalidArgument, "destination_provider_ids must not contain empty entries")
		}
	}
	if req.GuardrailIds != nil {
		for _, id := range *req.GuardrailIds {
			if strings.TrimSpace(id) == "" {
				return status.Errorf(status.InvalidArgument, "guardrail_ids must not contain empty entries")
			}
		}
	}
	if req.Limits != nil {
		if err := validatePolicyLimits(*req.Limits); err != nil {
			return err
		}
	}
	return nil
}

func validatePolicyLimits(l api.AgentNetworkPolicyLimits) error {
	if l.TokenLimit.Enabled {
		if l.TokenLimit.WindowSeconds < minWindowSeconds {
			return status.Errorf(status.InvalidArgument, "limits.token_limit.window_seconds must be at least %d (one minute) when enabled", minWindowSeconds)
		}
		if l.TokenLimit.GroupCap < 0 {
			return status.Errorf(status.InvalidArgument, "limits.token_limit.group_cap must not be negative")
		}
		if l.TokenLimit.UserCap < 0 {
			return status.Errorf(status.InvalidArgument, "limits.token_limit.user_cap must not be negative")
		}
		if l.TokenLimit.GroupCap == 0 && l.TokenLimit.UserCap == 0 {
			return status.Errorf(status.InvalidArgument, "limits.token_limit requires group_cap or user_cap to be greater than zero when enabled")
		}
	}
	if l.BudgetLimit.Enabled {
		if l.BudgetLimit.WindowSeconds < minWindowSeconds {
			return status.Errorf(status.InvalidArgument, "limits.budget_limit.window_seconds must be at least %d (one minute) when enabled", minWindowSeconds)
		}
		if l.BudgetLimit.GroupCapUsd < 0 {
			return status.Errorf(status.InvalidArgument, "limits.budget_limit.group_cap_usd must not be negative")
		}
		if l.BudgetLimit.UserCapUsd < 0 {
			return status.Errorf(status.InvalidArgument, "limits.budget_limit.user_cap_usd must not be negative")
		}
		if l.BudgetLimit.GroupCapUsd == 0 && l.BudgetLimit.UserCapUsd == 0 {
			return status.Errorf(status.InvalidArgument, "limits.budget_limit requires group_cap_usd or user_cap_usd to be greater than zero when enabled")
		}
	}
	return nil
}
