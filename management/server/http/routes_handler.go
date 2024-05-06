package http

import (
	"encoding/json"
	"net/http"
	"unicode/utf8"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/http/api"
	"github.com/netbirdio/netbird/management/server/http/util"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/route"
)

// RoutesHandler is the routes handler of the account
type RoutesHandler struct {
	accountManager  server.AccountManager
	claimsExtractor *jwtclaims.ClaimsExtractor
}

// NewRoutesHandler returns a new instance of RoutesHandler handler
func NewRoutesHandler(accountManager server.AccountManager, authCfg AuthCfg) *RoutesHandler {
	return &RoutesHandler{
		accountManager: accountManager,
		claimsExtractor: jwtclaims.NewClaimsExtractor(
			jwtclaims.WithAudience(authCfg.Audience),
			jwtclaims.WithUserIDClaim(authCfg.UserIDClaim),
		),
	}
}

// GetAllRoutes returns the list of routes for the account
func (h *RoutesHandler) GetAllRoutes(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	routes, err := h.accountManager.ListRoutes(account.Id, user.Id)
	if err != nil {
		util.WriteError(err, w)
		return
	}
	apiRoutes := make([]*api.Route, 0)
	for _, r := range routes {
		apiRoutes = append(apiRoutes, toRouteResponse(r))
	}

	util.WriteJSONObject(w, apiRoutes)
}

// CreateRoute handles route creation request
func (h *RoutesHandler) CreateRoute(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	var req api.PostApiRoutesJSONRequestBody
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	_, newPrefix, err := route.ParseNetwork(req.Network)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	if utf8.RuneCountInString(req.NetworkId) > route.MaxNetIDChar || req.NetworkId == "" {
		util.WriteError(status.Errorf(status.InvalidArgument, "identifier should be between 1 and %d",
			route.MaxNetIDChar), w)
		return
	}

	peerId := ""
	if req.Peer != nil {
		peerId = *req.Peer
	}

	peerGroupIds := []string{}
	if req.PeerGroups != nil {
		peerGroupIds = *req.PeerGroups
	}

	if (peerId != "" && len(peerGroupIds) > 0) || (peerId == "" && len(peerGroupIds) == 0) {
		util.WriteError(status.Errorf(status.InvalidArgument, "only one peer or peer_groups should be provided"), w)
		return
	}

	// do not allow non Linux peers
	if peer := account.GetPeer(peerId); peer != nil {
		if peer.Meta.GoOS != "linux" {
			util.WriteError(status.Errorf(status.InvalidArgument, "non-linux peers are non supported as network routes"), w)
			return
		}
	}

	newRoute, err := h.accountManager.CreateRoute(
		account.Id, newPrefix.String(), peerId, peerGroupIds,
		req.Description, route.NetID(req.NetworkId), req.Masquerade, req.Metric, req.Groups, req.Enabled, user.Id,
	)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	resp := toRouteResponse(newRoute)

	util.WriteJSONObject(w, &resp)
}

// UpdateRoute handles update to a route identified by a given ID
func (h *RoutesHandler) UpdateRoute(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	vars := mux.Vars(r)
	routeID := vars["routeId"]
	if len(routeID) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid route ID"), w)
		return
	}

	_, err = h.accountManager.GetRoute(account.Id, route.ID(routeID), user.Id)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	var req api.PutApiRoutesRouteIdJSONRequestBody
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	prefixType, newPrefix, err := route.ParseNetwork(req.Network)
	if err != nil {
		util.WriteError(status.Errorf(status.InvalidArgument, "couldn't parse update prefix %s for route ID %s",
			req.Network, routeID), w)
		return
	}

	if utf8.RuneCountInString(req.NetworkId) > route.MaxNetIDChar || req.NetworkId == "" {
		util.WriteError(status.Errorf(status.InvalidArgument,
			"identifier should be between 1 and %d", route.MaxNetIDChar), w)
		return
	}

	if req.Peer != nil && req.PeerGroups != nil {
		util.WriteError(status.Errorf(status.InvalidArgument, "only peer or peers_group should be provided"), w)
		return
	}

	if req.Peer == nil && req.PeerGroups == nil {
		util.WriteError(status.Errorf(status.InvalidArgument, "either peer or peers_group should be provided"), w)
		return
	}

	peerID := ""
	if req.Peer != nil {
		peerID = *req.Peer
	}

	// do not allow non Linux peers
	if peer := account.GetPeer(peerID); peer != nil {
		if peer.Meta.GoOS != "linux" {
			util.WriteError(status.Errorf(status.InvalidArgument, "non-linux peers are non supported as network routes"), w)
			return
		}
	}

	newRoute := &route.Route{
		ID:          route.ID(routeID),
		Network:     newPrefix,
		NetID:       route.NetID(req.NetworkId),
		NetworkType: prefixType,
		Masquerade:  req.Masquerade,
		Metric:      req.Metric,
		Description: req.Description,
		Enabled:     req.Enabled,
		Groups:      req.Groups,
	}

	if req.Peer != nil {
		newRoute.Peer = peerID
	}

	if req.PeerGroups != nil {
		newRoute.PeerGroups = *req.PeerGroups
	}

	err = h.accountManager.SaveRoute(account.Id, user.Id, newRoute)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	resp := toRouteResponse(newRoute)

	util.WriteJSONObject(w, &resp)
}

// DeleteRoute handles route deletion request
func (h *RoutesHandler) DeleteRoute(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	routeID := mux.Vars(r)["routeId"]
	if len(routeID) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid route ID"), w)
		return
	}

	err = h.accountManager.DeleteRoute(account.Id, route.ID(routeID), user.Id)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	util.WriteJSONObject(w, emptyObject{})
}

// GetRoute handles a route Get request identified by ID
func (h *RoutesHandler) GetRoute(w http.ResponseWriter, r *http.Request) {
	claims := h.claimsExtractor.FromRequestContext(r)
	account, user, err := h.accountManager.GetAccountFromToken(claims)
	if err != nil {
		util.WriteError(err, w)
		return
	}

	routeID := mux.Vars(r)["routeId"]
	if len(routeID) == 0 {
		util.WriteError(status.Errorf(status.InvalidArgument, "invalid route ID"), w)
		return
	}

	foundRoute, err := h.accountManager.GetRoute(account.Id, route.ID(routeID), user.Id)
	if err != nil {
		util.WriteError(status.Errorf(status.NotFound, "route not found"), w)
		return
	}

	util.WriteJSONObject(w, toRouteResponse(foundRoute))
}

func toRouteResponse(serverRoute *route.Route) *api.Route {
	route := &api.Route{
		Id:          string(serverRoute.ID),
		Description: serverRoute.Description,
		NetworkId:   string(serverRoute.NetID),
		Enabled:     serverRoute.Enabled,
		Peer:        &serverRoute.Peer,
		Network:     serverRoute.Network.String(),
		NetworkType: serverRoute.NetworkType.String(),
		Masquerade:  serverRoute.Masquerade,
		Metric:      serverRoute.Metric,
		Groups:      serverRoute.Groups,
	}

	if len(serverRoute.PeerGroups) > 0 {
		route.PeerGroups = &serverRoute.PeerGroups
	}
	return route
}
