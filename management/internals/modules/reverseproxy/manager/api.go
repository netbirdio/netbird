package manager

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/domain"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

type handler struct {
	manager reverseproxy.Manager
}

func RegisterEndpoints(manager reverseproxy.Manager, domainManager domain.Manager, router *mux.Router) {
	h := &handler{
		manager: manager,
	}

	router.HandleFunc("/reverse-proxies", h.getAllReverseProxies).Methods("GET", "OPTIONS")
	router.HandleFunc("/reverse-proxies", h.createReverseProxy).Methods("POST", "OPTIONS")
	router.HandleFunc("/reverse-proxies/{proxyId}", h.getReverseProxy).Methods("GET", "OPTIONS")
	router.HandleFunc("/reverse-proxies/{proxyId}", h.updateReverseProxy).Methods("PUT", "OPTIONS")
	router.HandleFunc("/reverse-proxies/{proxyId}", h.deleteReverseProxy).Methods("DELETE", "OPTIONS")

	// Hang domain endpoints off the main router here.
	domainRouter := router.PathPrefix("/reverse-proxies").Subrouter()
	domain.RegisterEndpoints(domainRouter, domainManager)
}

func (h *handler) getAllReverseProxies(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	allReverseProxies, err := h.manager.GetAllReverseProxies(r.Context(), userAuth.AccountId, userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	apiReverseProxies := make([]*api.ReverseProxy, 0, len(allReverseProxies))
	for _, reverseProxy := range allReverseProxies {
		apiReverseProxies = append(apiReverseProxies, reverseProxy.ToAPIResponse())
	}

	util.WriteJSONObject(r.Context(), w, apiReverseProxies)
}

func (h *handler) createReverseProxy(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	var req api.PostApiReverseProxyJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	reverseProxy := new(reverseproxy.ReverseProxy)
	reverseProxy.FromAPIRequest(&req, userAuth.AccountId)

	if err = reverseProxy.Validate(); err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "%s", err.Error()), w)
		return
	}

	createdReverseProxy, err := h.manager.CreateReverseProxy(r.Context(), userAuth.AccountId, userAuth.UserId, reverseProxy)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, createdReverseProxy.ToAPIResponse())
}

func (h *handler) getReverseProxy(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	reverseProxyID := mux.Vars(r)["proxyId"]
	if reverseProxyID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "reverse proxy ID is required"), w)
		return
	}

	reverseProxy, err := h.manager.GetReverseProxy(r.Context(), userAuth.AccountId, userAuth.UserId, reverseProxyID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, reverseProxy.ToAPIResponse())
}

func (h *handler) updateReverseProxy(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	reverseProxyID := mux.Vars(r)["proxyId"]
	if reverseProxyID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "reverse proxy ID is required"), w)
		return
	}

	var req api.PutApiReverseProxyProxyIdJSONRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	reverseProxy := new(reverseproxy.ReverseProxy)
	reverseProxy.ID = reverseProxyID
	reverseProxy.FromAPIRequest(&req, userAuth.AccountId)

	if err = reverseProxy.Validate(); err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "%s", err.Error()), w)
		return
	}

	updatedReverseProxy, err := h.manager.UpdateReverseProxy(r.Context(), userAuth.AccountId, userAuth.UserId, reverseProxy)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, updatedReverseProxy.ToAPIResponse())
}

func (h *handler) deleteReverseProxy(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	reverseProxyID := mux.Vars(r)["proxyId"]
	if reverseProxyID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "reverse proxy ID is required"), w)
		return
	}

	if err := h.manager.DeleteReverseProxy(r.Context(), userAuth.AccountId, userAuth.UserId, reverseProxyID); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, util.EmptyObject{})
}
