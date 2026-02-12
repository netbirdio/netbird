package manager

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/accesslogs"
	accesslogsmanager "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/accesslogs/manager"
	domainmanager "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/domain/manager"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

type handler struct {
	manager reverseproxy.Manager
}

// RegisterEndpoints registers all service HTTP endpoints.
func RegisterEndpoints(manager reverseproxy.Manager, domainManager domainmanager.Manager, accessLogsManager accesslogs.Manager, router *mux.Router) {
	h := &handler{
		manager: manager,
	}

	domainRouter := router.PathPrefix("/reverse-proxies").Subrouter()
	domainmanager.RegisterEndpoints(domainRouter, domainManager)

	accesslogsmanager.RegisterEndpoints(router, accessLogsManager)

	router.HandleFunc("/reverse-proxies/services", h.getAllServices).Methods("GET", "OPTIONS")
	router.HandleFunc("/reverse-proxies/services", h.createService).Methods("POST", "OPTIONS")
	router.HandleFunc("/reverse-proxies/services/{serviceId}", h.getService).Methods("GET", "OPTIONS")
	router.HandleFunc("/reverse-proxies/services/{serviceId}", h.updateService).Methods("PUT", "OPTIONS")
	router.HandleFunc("/reverse-proxies/services/{serviceId}", h.deleteService).Methods("DELETE", "OPTIONS")
}

func (h *handler) getAllServices(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	allServices, err := h.manager.GetAllServices(r.Context(), userAuth.AccountId, userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	apiServices := make([]*api.Service, 0, len(allServices))
	for _, service := range allServices {
		apiServices = append(apiServices, service.ToAPIResponse())
	}

	util.WriteJSONObject(r.Context(), w, apiServices)
}

func (h *handler) createService(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	var req api.ServiceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	service := new(reverseproxy.Service)
	service.FromAPIRequest(&req, userAuth.AccountId)

	if err = service.Validate(); err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "%s", err.Error()), w)
		return
	}

	createdService, err := h.manager.CreateService(r.Context(), userAuth.AccountId, userAuth.UserId, service)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, createdService.ToAPIResponse())
}

func (h *handler) getService(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	serviceID := mux.Vars(r)["serviceId"]
	if serviceID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "service ID is required"), w)
		return
	}

	service, err := h.manager.GetService(r.Context(), userAuth.AccountId, userAuth.UserId, serviceID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, service.ToAPIResponse())
}

func (h *handler) updateService(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	serviceID := mux.Vars(r)["serviceId"]
	if serviceID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "service ID is required"), w)
		return
	}

	var req api.ServiceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	service := new(reverseproxy.Service)
	service.ID = serviceID
	service.FromAPIRequest(&req, userAuth.AccountId)

	if err = service.Validate(); err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "%s", err.Error()), w)
		return
	}

	updatedService, err := h.manager.UpdateService(r.Context(), userAuth.AccountId, userAuth.UserId, service)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, updatedService.ToAPIResponse())
}

func (h *handler) deleteService(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	serviceID := mux.Vars(r)["serviceId"]
	if serviceID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "service ID is required"), w)
		return
	}

	if err := h.manager.DeleteService(r.Context(), userAuth.AccountId, userAuth.UserId, serviceID); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, util.EmptyObject{})
}
