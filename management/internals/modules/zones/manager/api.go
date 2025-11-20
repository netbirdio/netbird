package manager

import (
	"net/http"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/internals/modules/zones"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/shared/management/http/util"
)

type handler struct {
	manager            zones.Manager
	permissionsManager permissions.Manager
}

func RegisterEndpoints(router *mux.Router, manager zones.Manager) {
	h := &handler{
		manager: manager,
	}

	router.HandleFunc("/dns/zones", h.getAllZones).Methods("GET", "OPTIONS")
	router.HandleFunc("/dns/zones", nil).Methods("POST", "OPTIONS")
	router.HandleFunc("/dns/zones/{id}", nil).Methods("GET", "OPTIONS")
	router.HandleFunc("/dns/zones/{id}", nil).Methods("PUT", "OPTIONS")
	router.HandleFunc("/dns/zones/{id}", nil).Methods("DELETE", "OPTIONS")
}

func (h *handler) getAllZones(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	allZones, err := h.manager.GetAllZones(r.Context(), userAuth.AccountId, userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, allZones)
}
