package networks

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/networks/routers"
	"github.com/netbirdio/netbird/management/server/networks/routers/types"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
)

type routersHandler struct {
	routersManager routers.Manager
}

func addRouterEndpoints(routersManager routers.Manager, router *mux.Router) {
	routersHandler := newRoutersHandler(routersManager)
	router.HandleFunc("/networks/routers", routersHandler.getAllRouters).Methods("GET", "OPTIONS")
	router.HandleFunc("/networks/{networkId}/routers", routersHandler.getNetworkRouters).Methods("GET", "OPTIONS")
	router.HandleFunc("/networks/{networkId}/routers", routersHandler.createRouter).Methods("POST", "OPTIONS")
	router.HandleFunc("/networks/{networkId}/routers/{routerId}", routersHandler.getRouter).Methods("GET", "OPTIONS")
	router.HandleFunc("/networks/{networkId}/routers/{routerId}", routersHandler.updateRouter).Methods("PUT", "OPTIONS")
	router.HandleFunc("/networks/{networkId}/routers/{routerId}", routersHandler.deleteRouter).Methods("DELETE", "OPTIONS")
}

func newRoutersHandler(routersManager routers.Manager) *routersHandler {
	return &routersHandler{
		routersManager: routersManager,
	}
}

func (h *routersHandler) getAllRouters(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId

	routersMap, err := h.routersManager.GetAllRoutersInAccount(r.Context(), accountID, userID)
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

func (h *routersHandler) getNetworkRouters(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId

	networkID := mux.Vars(r)["networkId"]
	routers, err := h.routersManager.GetAllRoutersInNetwork(r.Context(), accountID, userID, networkID)
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

func (h *routersHandler) createRouter(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId

	networkID := mux.Vars(r)["networkId"]
	var req api.NetworkRouterRequest
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	router := &types.NetworkRouter{}
	router.FromAPIRequest(&req)

	router.NetworkID = networkID
	router.AccountID = accountID
	router.Enabled = true
	router, err = h.routersManager.CreateRouter(r.Context(), userID, router)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, router.ToAPIResponse())
}

func (h *routersHandler) getRouter(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId

	routerID := mux.Vars(r)["routerId"]
	networkID := mux.Vars(r)["networkId"]
	router, err := h.routersManager.GetRouter(r.Context(), accountID, userID, networkID, routerID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, router.ToAPIResponse())
}

func (h *routersHandler) updateRouter(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId

	var req api.NetworkRouterRequest
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	router := &types.NetworkRouter{}
	router.FromAPIRequest(&req)

	router.NetworkID = mux.Vars(r)["networkId"]
	router.ID = mux.Vars(r)["routerId"]
	router.AccountID = accountID

	router, err = h.routersManager.UpdateRouter(r.Context(), userID, router)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, router.ToAPIResponse())
}

func (h *routersHandler) deleteRouter(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId
	routerID := mux.Vars(r)["routerId"]
	networkID := mux.Vars(r)["networkId"]
	err = h.routersManager.DeleteRouter(r.Context(), accountID, userID, networkID, routerID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, struct{}{})
}
