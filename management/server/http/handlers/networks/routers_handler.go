package networks

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/http/configs"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/networks/routers"
	"github.com/netbirdio/netbird/management/server/networks/routers/types"
)

type routersHandler struct {
	routersManager   routers.Manager
	extractFromToken func(ctx context.Context, claims jwtclaims.AuthorizationClaims) (string, string, error)
	claimsExtractor  *jwtclaims.ClaimsExtractor
}

func addRouterEndpoints(routersManager routers.Manager, extractFromToken func(ctx context.Context, claims jwtclaims.AuthorizationClaims) (string, string, error), authCfg configs.AuthCfg, router *mux.Router) {
	routersHandler := newRoutersHandler(routersManager, extractFromToken, authCfg)
	router.HandleFunc("/networks/{networkId}/routers", routersHandler.getAllRouters).Methods("GET", "OPTIONS")
	router.HandleFunc("/networks/{networkId}/routers", routersHandler.createRouter).Methods("POST", "OPTIONS")
	router.HandleFunc("/networks/{networkId}/routers/{routerId}", routersHandler.getRouter).Methods("GET", "OPTIONS")
	router.HandleFunc("/networks/{networkId}/routers/{routerId}", routersHandler.updateRouter).Methods("PUT", "OPTIONS")
	router.HandleFunc("/networks/{networkId}/routers/{routerId}", routersHandler.deleteRouter).Methods("DELETE", "OPTIONS")
}

func newRoutersHandler(routersManager routers.Manager, extractFromToken func(ctx context.Context, claims jwtclaims.AuthorizationClaims) (string, string, error), authCfg configs.AuthCfg) *routersHandler {
	return &routersHandler{
		routersManager:   routersManager,
		extractFromToken: extractFromToken,
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithAudience(authCfg.Audience),
			jwtclaims.WithUserIDClaim(authCfg.UserIDClaim),
		),
	}
}

func (h *routersHandler) getAllRouters(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.extractFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	networkID := mux.Vars(r)["networkId"]
	routers, err := h.routersManager.GetAllRoutersInNetwork(r.Context(), accountID, userID, networkID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	var routersResponse []*api.NetworkRouter
	for _, router := range routers {
		routersResponse = append(routersResponse, router.ToAPIResponse())
	}

	util.WriteJSONObject(r.Context(), w, routersResponse)
}

func (h *routersHandler) createRouter(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.extractFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

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
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.extractFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

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
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.extractFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

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
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.extractFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	routerID := mux.Vars(r)["routerId"]
	networkID := mux.Vars(r)["networkId"]
	err = h.routersManager.DeleteRouter(r.Context(), accountID, userID, networkID, routerID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, struct{}{})
}
