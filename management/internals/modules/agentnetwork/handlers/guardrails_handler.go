package handlers

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

// addGuardrailEndpoints registers all Agent Network guardrail routes.
func (h *handler) addGuardrailEndpoints(router *mux.Router) {
	router.HandleFunc("/agent-network/guardrails", h.getAllGuardrails).Methods("GET", "OPTIONS")
	router.HandleFunc("/agent-network/guardrails", h.createGuardrail).Methods("POST", "OPTIONS")
	router.HandleFunc("/agent-network/guardrails/{guardrailId}", h.getGuardrail).Methods("GET", "OPTIONS")
	router.HandleFunc("/agent-network/guardrails/{guardrailId}", h.updateGuardrail).Methods("PUT", "OPTIONS")
	router.HandleFunc("/agent-network/guardrails/{guardrailId}", h.deleteGuardrail).Methods("DELETE", "OPTIONS")
}

func (h *handler) getAllGuardrails(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	guardrails, err := h.manager.GetAllGuardrails(r.Context(), userAuth.AccountId, userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	out := make([]*api.AgentNetworkGuardrail, 0, len(guardrails))
	for _, g := range guardrails {
		out = append(out, g.ToAPIResponse())
	}
	util.WriteJSONObject(r.Context(), w, out)
}

func (h *handler) getGuardrail(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	guardrailID := mux.Vars(r)["guardrailId"]
	if guardrailID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "guardrail ID is required"), w)
		return
	}

	guardrail, err := h.manager.GetGuardrail(r.Context(), userAuth.AccountId, userAuth.UserId, guardrailID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, guardrail.ToAPIResponse())
}

func (h *handler) createGuardrail(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	var req api.AgentNetworkGuardrailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	if err := validateGuardrail(&req); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	guardrail := types.NewGuardrail(userAuth.AccountId)
	guardrail.FromAPIRequest(&req)

	created, err := h.manager.CreateGuardrail(r.Context(), userAuth.UserId, guardrail)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, created.ToAPIResponse())
}

func (h *handler) updateGuardrail(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	guardrailID := mux.Vars(r)["guardrailId"]
	if guardrailID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "guardrail ID is required"), w)
		return
	}

	var req api.AgentNetworkGuardrailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	if err := validateGuardrail(&req); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	guardrail := &types.Guardrail{
		ID:        guardrailID,
		AccountID: userAuth.AccountId,
	}
	guardrail.FromAPIRequest(&req)

	updated, err := h.manager.UpdateGuardrail(r.Context(), userAuth.UserId, guardrail)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, updated.ToAPIResponse())
}

func (h *handler) deleteGuardrail(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	guardrailID := mux.Vars(r)["guardrailId"]
	if guardrailID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "guardrail ID is required"), w)
		return
	}

	if err := h.manager.DeleteGuardrail(r.Context(), userAuth.AccountId, userAuth.UserId, guardrailID); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, util.EmptyObject{})
}

func validateGuardrail(req *api.AgentNetworkGuardrailRequest) error {
	if strings.TrimSpace(req.Name) == "" {
		return status.Errorf(status.InvalidArgument, "name is required")
	}

	c := req.Checks
	if c.ModelAllowlist.Enabled {
		for _, id := range c.ModelAllowlist.Models {
			if strings.TrimSpace(id) == "" {
				return status.Errorf(status.InvalidArgument, "model_allowlist.models must not contain empty entries")
			}
		}
	}
	return nil
}
