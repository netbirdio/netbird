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
	"github.com/netbirdio/netbird/management/server/networks"
	"github.com/netbirdio/netbird/management/server/status"
)

// handler is a handler that returns networks of the account
type handler struct {
	networksManager  networks.Manager
	extractFromToken func(ctx context.Context, claims jwtclaims.AuthorizationClaims) (string, string, error)
	claimsExtractor  *jwtclaims.ClaimsExtractor
}

func AddEndpoints(networksManager networks.Manager, extractFromToken func(ctx context.Context, claims jwtclaims.AuthorizationClaims) (string, string, error), authCfg configs.AuthCfg, router *mux.Router) {
	networksHandler := newHandler(networksManager, extractFromToken, authCfg)
	router.HandleFunc("/networks", networksHandler.getAllNetworks).Methods("GET", "OPTIONS")
	router.HandleFunc("/networks", networksHandler.createNetwork).Methods("POST", "OPTIONS")
	router.HandleFunc("/networks/{networkId}", networksHandler.getNetwork).Methods("GET", "OPTIONS")
	router.HandleFunc("/networks/{networkId}", networksHandler.updateNetwork).Methods("PUT", "OPTIONS")
	router.HandleFunc("/networks/{networkId}", networksHandler.deleteNetwork).Methods("DELETE", "OPTIONS")
	addRouterEndpoints(networksManager.GetRouterManager(), extractFromToken, authCfg, router)
	addResourceEndpoints(networksManager.GetResourceManager(), extractFromToken, authCfg, router)
}

func newHandler(networksManager networks.Manager, extractFromToken func(ctx context.Context, claims jwtclaims.AuthorizationClaims) (string, string, error), authCfg configs.AuthCfg) *handler {
	return &handler{
		networksManager:  networksManager,
		extractFromToken: extractFromToken,
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithAudience(authCfg.Audience),
			jwtclaims.WithUserIDClaim(authCfg.UserIDClaim),
		),
	}
}

func (h *handler) getAllNetworks(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.extractFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	networks, err := h.networksManager.GetAllNetworks(r.Context(), accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	var networkResponse []*api.Network
	for _, network := range networks {
		networkResponse = append(networkResponse, network.ToAPIResponse())
	}

	util.WriteJSONObject(r.Context(), w, networkResponse)
}

func (h *handler) createNetwork(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.extractFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	var req api.NetworkRequest
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	network := &networks.Network{}
	network.FromAPIRequest(&req)

	network.AccountID = accountID
	network, err = h.networksManager.CreateNetwork(r.Context(), userID, network)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, network.ToAPIResponse())
}

func (h *handler) getNetwork(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.extractFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	vars := mux.Vars(r)
	networkID := vars["networkId"]
	if len(networkID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid network ID"), w)
		return
	}

	network, err := h.networksManager.GetNetwork(r.Context(), accountID, userID, networkID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, network.ToAPIResponse())
}

func (h *handler) updateNetwork(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.extractFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	vars := mux.Vars(r)
	networkID := vars["networkId"]
	if len(networkID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid network ID"), w)
		return
	}

	var req api.NetworkRequest
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	network := &networks.Network{}
	network.FromAPIRequest(&req)

	network.ID = networkID
	network.AccountID = accountID
	network, err = h.networksManager.UpdateNetwork(r.Context(), userID, network)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, network.ToAPIResponse())
}

func (h *handler) deleteNetwork(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	accountID, userID, err := h.extractFromToken(r.Context(), claims)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	vars := mux.Vars(r)
	networkID := vars["networkId"]
	if len(networkID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid network ID"), w)
		return
	}

	err = h.networksManager.DeleteNetwork(r.Context(), accountID, userID, networkID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, util.EmptyObject{})
}
