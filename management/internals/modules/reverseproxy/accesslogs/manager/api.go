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

	logs, err := h.manager.GetAllAccessLogs(r.Context(), userAuth.AccountId, userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	apiLogs := make([]api.ProxyAccessLog, 0, len(logs))
	for _, log := range logs {
		apiLogs = append(apiLogs, *log.ToAPIResponse())
	}

	util.WriteJSONObject(r.Context(), w, apiLogs)
}
