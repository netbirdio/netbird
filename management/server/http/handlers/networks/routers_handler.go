package networks

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/internals/modules/permissions"
	"github.com/netbirdio/netbird/management/internals/modules/permissions/modules"
	"github.com/netbirdio/netbird/management/internals/modules/permissions/operations"
	"github.com/netbirdio/netbird/management/server/networks/routers"
	"github.com/netbirdio/netbird/management/server/networks/routers/types"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
)

type routersHandler struct {
	routersManager routers.Manager
}

func addRouterEndpoints(routersManager routers.Manager, permissionsManager permissions.Manager, router *mux.Router) {
	routersHandler := newRoutersHandler(routersManager)
	router.HandleFunc("/networks/routers", permissionsManager.WithPermission(modules.Networks, operations.Read, routersHandler.getAllRouters)).Methods("GET", "OPTIONS")
	router.HandleFunc("/networks/{networkId}/routers", permissionsManager.WithPermission(modules.Networks, operations.Read, routersHandler.getNetworkRouters)).Methods("GET", "OPTIONS")
	router.HandleFunc("/networks/{networkId}/routers", permissionsManager.WithPermission(modules.Networks, operations.Create, routersHandler.createRouter)).Methods("POST", "OPTIONS")
	router.HandleFunc("/networks/{networkId}/routers/{routerId}", permissionsManager.WithPermission(modules.Networks, operations.Read, routersHandler.getRouter)).Methods("GET", "OPTIONS")
	router.HandleFunc("/networks/{networkId}/routers/{routerId}", permissionsManager.WithPermission(modules.Networks, operations.Update, routersHandler.updateRouter)).Methods("PUT", "OPTIONS")
	router.HandleFunc("/networks/{networkId}/routers/{routerId}", permissionsManager.WithPermission(modules.Networks, operations.Delete, routersHandler.deleteRouter)).Methods("DELETE", "OPTIONS")
}

func newRoutersHandler(routersManager routers.Manager) *routersHandler {
	return &routersHandler{
		routersManager: routersManager,
	}
}

func (h *routersHandler) getAllRouters(w http.ResponseWriter, r *http.Request, userAuth *auth.UserAuth) {
	routersMap, err := h.routersManager.GetAllRoutersInAccount(r.Context(), userAuth.AccountId, userAuth.UserId)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	routersResponse := make([]*api.NetworkRouter, 0)
	for _, routers := range routersMap {
		for _, router := range routers {
			routersResponse = append(routersResponse, router.ToAPIResponse())
		}
	}

	util.WriteJSONObject(r.Context(), w, routersResponse)
}

func (h *routersHandler) getNetworkRouters(w http.ResponseWriter, r *http.Request, userAuth *auth.UserAuth) {
	networkID := mux.Vars(r)["networkId"]
	routers, err := h.routersManager.GetAllRoutersInNetwork(r.Context(), userAuth.AccountId, userAuth.UserId, networkID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	routersResponse := make([]*api.NetworkRouter, 0, len(routers))
	for _, router := range routers {
		routersResponse = append(routersResponse, router.ToAPIResponse())
	}

	util.WriteJSONObject(r.Context(), w, routersResponse)
}

func (h *routersHandler) createRouter(w http.ResponseWriter, r *http.Request, userAuth *auth.UserAuth) {
	networkID := mux.Vars(r)["networkId"]
	var req api.NetworkRouterRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	router := &types.NetworkRouter{}
	router.FromAPIRequest(&req)

	router.NetworkID = networkID
	router.AccountID = userAuth.AccountId
	router.Enabled = true
	router, err = h.routersManager.CreateRouter(r.Context(), userAuth.UserId, router)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, router.ToAPIResponse())
}

func (h *routersHandler) getRouter(w http.ResponseWriter, r *http.Request, userAuth *auth.UserAuth) {
	routerID := mux.Vars(r)["routerId"]
	networkID := mux.Vars(r)["networkId"]
	router, err := h.routersManager.GetRouter(r.Context(), userAuth.AccountId, userAuth.UserId, networkID, routerID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, router.ToAPIResponse())
}

func (h *routersHandler) updateRouter(w http.ResponseWriter, r *http.Request, userAuth *auth.UserAuth) {
	var req api.NetworkRouterRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	router := &types.NetworkRouter{}
	router.FromAPIRequest(&req)

	router.NetworkID = mux.Vars(r)["networkId"]
	router.ID = mux.Vars(r)["routerId"]
	router.AccountID = userAuth.AccountId

	router, err = h.routersManager.UpdateRouter(r.Context(), userAuth.UserId, router)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, router.ToAPIResponse())
}

func (h *routersHandler) deleteRouter(w http.ResponseWriter, r *http.Request, userAuth *auth.UserAuth) {
	routerID := mux.Vars(r)["routerId"]
	networkID := mux.Vars(r)["networkId"]
	err := h.routersManager.DeleteRouter(r.Context(), userAuth.AccountId, userAuth.UserId, networkID, routerID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, struct{}{})
}
