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

// addAccessLogEndpoints registers the read-only, server-side-filtered
// agent-network access-log listing and the aggregated usage overview.
func (h *handler) addAccessLogEndpoints(router *mux.Router) {
	router.HandleFunc("/agent-network/access-logs", h.listAccessLogs).Methods("GET", "OPTIONS")
	router.HandleFunc("/agent-network/usage/overview", h.getUsageOverview).Methods("GET", "OPTIONS")
}

func (h *handler) getUsageOverview(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	// Reuse the access-log filter for the shared date/user/group/provider/model
	// params; pagination/sort/search are irrelevant for an aggregate.
	var filter types.AgentNetworkAccessLogFilter
	if err := filter.ParseFromRequest(r); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	// Bound the aggregation window so an unbounded or over-wide query can't load
	// an account's entire usage history into memory.
	filter.ApplyUsageOverviewBounds(time.Now())
	granularity := types.ParseUsageGranularity(r.URL.Query().Get("granularity"))

	buckets, err := h.manager.GetUsageOverview(r.Context(), userAuth.AccountId, userAuth.UserId, filter, granularity)
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

func (h *handler) listAccessLogs(w http.ResponseWriter, r *http.Request) {
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

	rows, total, err := h.manager.ListAccessLogs(r.Context(), userAuth.AccountId, userAuth.UserId, filter)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	data := make([]api.AgentNetworkAccessLog, 0, len(rows))
	for _, row := range rows {
		data = append(data, row.ToAPIResponse())
	}

	pageSize := filter.GetLimit()
	totalPages := 0
	if pageSize > 0 {
		totalPages = int((total + int64(pageSize) - 1) / int64(pageSize))
	}

	util.WriteJSONObject(r.Context(), w, api.AgentNetworkAccessLogsResponse{
		Data:         data,
		Page:         filter.Page,
		PageSize:     pageSize,
		TotalRecords: int(total),
		TotalPages:   totalPages,
	})
}
