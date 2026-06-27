package agentnetwork

import (
	"net/http"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
)

// addConsumptionEndpoints registers the read-only Agent Network
// consumption listing — backs the dashboard's basic counter view.
func (h *handler) addConsumptionEndpoints(router *mux.Router) {
	router.HandleFunc("/agent-network/consumption", h.listConsumption).Methods("GET", "OPTIONS")
}

func (h *handler) listConsumption(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	rows, err := h.manager.ListConsumption(r.Context(), userAuth.AccountId, userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	out := make([]api.AgentNetworkConsumption, 0, len(rows))
	for _, row := range rows {
		out = append(out, consumptionToAPI(row))
	}
	util.WriteJSONObject(r.Context(), w, out)
}

func consumptionToAPI(c *types.Consumption) api.AgentNetworkConsumption {
	windowStart := c.WindowStartUTC
	updatedAt := c.UpdatedAt
	return api.AgentNetworkConsumption{
		DimensionKind:  api.AgentNetworkConsumptionDimensionKind(c.DimensionKind),
		DimensionId:    c.DimensionID,
		WindowSeconds:  c.WindowSeconds,
		WindowStartUtc: windowStart,
		TokensInput:    c.TokensInput,
		TokensOutput:   c.TokensOutput,
		CostUsd:        c.CostUSD,
		UpdatedAt:      &updatedAt,
	}
}
