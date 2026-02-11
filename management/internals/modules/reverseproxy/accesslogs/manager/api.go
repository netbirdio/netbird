package manager

import (
	"net/http"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/accesslogs"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
)

type handler struct {
	manager accesslogs.Manager
}

func RegisterEndpoints(router *mux.Router, manager accesslogs.Manager) {
	h := &handler{
		manager: manager,
	}

	router.HandleFunc("/events/proxy", h.getAccessLogs).Methods("GET", "OPTIONS")
}

func (h *handler) getAccessLogs(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	var filter accesslogs.AccessLogFilter
	filter.ParseFromRequest(r)

	logs, totalCount, err := h.manager.GetAllAccessLogs(r.Context(), userAuth.AccountId, userAuth.UserId, &filter)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	apiLogs := make([]api.ProxyAccessLog, 0, len(logs))
	for _, log := range logs {
		apiLogs = append(apiLogs, *log.ToAPIResponse())
	}

	response := &api.ProxyAccessLogsResponse{
		Data:         apiLogs,
		Page:         filter.Page,
		PageSize:     filter.PageSize,
		TotalRecords: int(totalCount),
		TotalPages:   getTotalPageCount(int(totalCount), filter.PageSize),
	}

	util.WriteJSONObject(r.Context(), w, response)
}

// getTotalPageCount calculates the total number of pages
func getTotalPageCount(totalCount, pageSize int) int {
	if pageSize <= 0 {
		return 0
	}
	return (totalCount + pageSize - 1) / pageSize
}
