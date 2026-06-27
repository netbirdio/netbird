package agentnetwork

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

// addBudgetRuleEndpoints registers the account-level budget rule routes.
func (h *handler) addBudgetRuleEndpoints(router *mux.Router) {
	router.HandleFunc("/agent-network/budget-rules", h.getAllBudgetRules).Methods("GET", "OPTIONS")
	router.HandleFunc("/agent-network/budget-rules", h.createBudgetRule).Methods("POST", "OPTIONS")
	router.HandleFunc("/agent-network/budget-rules/{ruleId}", h.getBudgetRule).Methods("GET", "OPTIONS")
	router.HandleFunc("/agent-network/budget-rules/{ruleId}", h.updateBudgetRule).Methods("PUT", "OPTIONS")
	router.HandleFunc("/agent-network/budget-rules/{ruleId}", h.deleteBudgetRule).Methods("DELETE", "OPTIONS")
}

func (h *handler) getAllBudgetRules(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	rules, err := h.manager.GetAllBudgetRules(r.Context(), userAuth.AccountId, userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	out := make([]*api.AgentNetworkBudgetRule, 0, len(rules))
	for _, rule := range rules {
		out = append(out, rule.ToAPIResponse())
	}
	util.WriteJSONObject(r.Context(), w, out)
}

func (h *handler) getBudgetRule(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	ruleID := mux.Vars(r)["ruleId"]
	if ruleID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "budget rule ID is required"), w)
		return
	}

	rule, err := h.manager.GetBudgetRule(r.Context(), userAuth.AccountId, userAuth.UserId, ruleID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, rule.ToAPIResponse())
}

func (h *handler) createBudgetRule(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	var req api.AgentNetworkBudgetRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	if err := validateBudgetRule(&req); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	rule := types.NewAccountBudgetRule(userAuth.AccountId)
	rule.FromAPIRequest(&req)

	created, err := h.manager.CreateBudgetRule(r.Context(), userAuth.UserId, rule)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, created.ToAPIResponse())
}

func (h *handler) updateBudgetRule(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	ruleID := mux.Vars(r)["ruleId"]
	if ruleID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "budget rule ID is required"), w)
		return
	}

	var req api.AgentNetworkBudgetRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	if err := validateBudgetRule(&req); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	rule := &types.AccountBudgetRule{ID: ruleID, AccountID: userAuth.AccountId}
	rule.FromAPIRequest(&req)

	updated, err := h.manager.UpdateBudgetRule(r.Context(), userAuth.UserId, rule)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, updated.ToAPIResponse())
}

func (h *handler) deleteBudgetRule(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	ruleID := mux.Vars(r)["ruleId"]
	if ruleID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "budget rule ID is required"), w)
		return
	}

	if err := h.manager.DeleteBudgetRule(r.Context(), userAuth.AccountId, userAuth.UserId, ruleID); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, util.EmptyObject{})
}

// validateBudgetRule rejects malformed budget rules. It reuses the policy limit
// validation since the cap shape is identical, and rejects empty target entries.
func validateBudgetRule(req *api.AgentNetworkBudgetRuleRequest) error {
	if strings.TrimSpace(req.Name) == "" {
		return status.Errorf(status.InvalidArgument, "name is required")
	}
	if req.TargetGroups != nil {
		for _, id := range *req.TargetGroups {
			if strings.TrimSpace(id) == "" {
				return status.Errorf(status.InvalidArgument, "target_groups must not contain empty entries")
			}
		}
	}
	if req.TargetUsers != nil {
		for _, id := range *req.TargetUsers {
			if strings.TrimSpace(id) == "" {
				return status.Errorf(status.InvalidArgument, "target_users must not contain empty entries")
			}
		}
	}
	return validatePolicyLimits(req.Limits)
}
