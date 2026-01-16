package manager

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/internals/modules/services"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

type handler struct {
	manager services.Manager
}

func RegisterEndpoints(router *mux.Router, manager services.Manager) {
	h := &handler{
		manager: manager,
	}

	router.HandleFunc("/services", h.getAllServices).Methods("GET", "OPTIONS")
	router.HandleFunc("/services", h.createService).Methods("POST", "OPTIONS")
	router.HandleFunc("/services/{serviceId}", h.getService).Methods("GET", "OPTIONS")
	router.HandleFunc("/services/{serviceId}", h.updateService).Methods("PUT", "OPTIONS")
	router.HandleFunc("/services/{serviceId}", h.deleteService).Methods("DELETE", "OPTIONS")
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

	var req api.PostApiServicesJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	service := new(services.Service)
	service.FromAPIRequest(&req)

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

	var req api.PutApiServicesServiceIdJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	service := new(services.Service)
	service.ID = serviceID
	service.FromAPIRequest(&req)

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
