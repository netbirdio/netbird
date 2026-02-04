package manager

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/accesslogs"
	accesslogsmanager "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/accesslogs/manager"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/domain"
	nbgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

type clusterProvider interface {
	GetAvailableClusters() []nbgrpc.ClusterInfo
}

type handler struct {
	manager         reverseproxy.Manager
	clusterProvider clusterProvider
}

// RegisterEndpoints registers all reverse proxy HTTP endpoints.
func RegisterEndpoints(manager reverseproxy.Manager, domainManager domain.Manager, accessLogsManager accesslogs.Manager, clusterProvider clusterProvider, router *mux.Router) {
	h := &handler{
		manager:         manager,
		clusterProvider: clusterProvider,
	}

	domainRouter := router.PathPrefix("/reverse-proxies").Subrouter()
	domain.RegisterEndpoints(domainRouter, domainManager)

	accesslogsmanager.RegisterEndpoints(router, accessLogsManager)

	router.HandleFunc("/reverse-proxies", h.getAllReverseProxies).Methods("GET", "OPTIONS")
	router.HandleFunc("/reverse-proxies", h.createReverseProxy).Methods("POST", "OPTIONS")
	router.HandleFunc("/reverse-proxies/clusters", h.getAvailableClusters).Methods("GET", "OPTIONS")
	router.HandleFunc("/reverse-proxies/{proxyId}", h.getReverseProxy).Methods("GET", "OPTIONS")
	router.HandleFunc("/reverse-proxies/{proxyId}", h.updateReverseProxy).Methods("PUT", "OPTIONS")
	router.HandleFunc("/reverse-proxies/{proxyId}", h.deleteReverseProxy).Methods("DELETE", "OPTIONS")
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

	var req api.ReverseProxyRequest
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

	var req api.ReverseProxyRequest
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

func (h *handler) getAvailableClusters(w http.ResponseWriter, r *http.Request) {
	_, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	clusters := h.clusterProvider.GetAvailableClusters()
	apiClusters := make([]api.ProxyCluster, 0, len(clusters))
	for _, c := range clusters {
		apiClusters = append(apiClusters, api.ProxyCluster{
			Address:          c.Address,
			ConnectedProxies: c.ConnectedProxies,
		})
	}

	util.WriteJSONObject(r.Context(), w, apiClusters)
}
